import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
APPLE_WORKFLOW = WORKFLOW_DIRECTORY / "apple-artifact.yml"
RELEASE_EVIDENCE_WORKFLOW = WORKFLOW_DIRECTORY / "release-evidence-finalize.yml"
PILOT_SIGNOFF_WORKFLOW = WORKFLOW_DIRECTORY / "pilot-signoff-ingest.yml"
PROMOTION_WORKFLOW = WORKFLOW_DIRECTORY / "promotion-gate.yml"
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

    @staticmethod
    def release_evidence_workflow() -> str:
        return RELEASE_EVIDENCE_WORKFLOW.read_text(encoding="utf-8")

    @staticmethod
    def pilot_signoff_workflow() -> str:
        return PILOT_SIGNOFF_WORKFLOW.read_text(encoding="utf-8")

    @staticmethod
    def promotion_workflow() -> str:
        return PROMOTION_WORKFLOW.read_text(encoding="utf-8")

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

    def test_release_evidence_uses_exact_runs_and_release_revision(self):
        workflow = self.release_evidence_workflow()
        for required_input in (
            "release_revision:",
            "promotion_run_id:",
            "promotion_run_attempt:",
            "apple_run_id:",
            "apple_run_attempt:",
        ):
            self.assertIn(required_input, workflow)
        for invariant in (
            'PROMOTION_WORKFLOW_ID: "246571367"',
            'APPLE_WORKFLOW_ID: "320479820"',
            'test "$(git rev-parse HEAD)" = "$RELEASE_REVISION"',
            'run.get("head_sha") != os.environ["RELEASE_REVISION"]',
            'run.get("run_attempt") != expected_attempt',
            'test "$PROMOTION_RUN_ATTEMPT" = "1"',
            'test "$APPLE_RUN_ATTEMPT" = "1"',
            'run.get("status") != "completed" or run.get("conclusion") != "success"',
            'run.get("event") not in expected_events',
            'expected_events={"workflow_dispatch"}',
            'expected_events={"workflow_dispatch", "push"}',
            'head_repository.get("full_name") != expected_repo',
            "expected exactly one artifact named",
            'artifact.get("expired") is not False',
            'sha256:[0-9a-f]{64}',
        ):
            self.assertIn(invariant, workflow)
        self.assertNotIn("gh run list", workflow)
        self.assertNotIn("--limit", workflow)
        self.assertNotIn("pull_request", workflow.split("on:", 1)[1].split("jobs:", 1)[0])

    def test_release_evidence_profile_never_silently_omits_production_children(self):
        workflow = self.release_evidence_workflow()
        build_step = workflow.split("- name: Build exact final evidence manifest", 1)[1].split(
            "- name: Upload frozen unsigned evidence", 1
        )[0]
        for required_argument in (
            "--pilot-gate-report incoming/promotion/pilot-gate-report.json",
            "--pilot-signoff-verification incoming/promotion/pilot-signoff-verification.json",
            "--kids-preprod-dry-run-report incoming/promotion/kids-preprod-dry-run-matrix.json",
            "--apple-artifact-verification incoming/apple/apple-release-verification.json",
            "--apple-artifact-reproducibility incoming/apple/apple-reproducibility.json",
            "incoming/apple/apple-verified-dist/release-manifest.json",
            '"$package/release-inputs/pilot/pilot-signoff-verification.json"',
        ):
            self.assertIn(required_argument, build_step)
        self.assertNotIn("if [ -f", build_step)
        self.assertNotIn("|| true", build_step)

    def test_release_evidence_freeze_has_no_signing_key_or_go_authority(self):
        workflow = self.release_evidence_workflow()
        self.assertIn("name: Release Evidence Freeze", workflow)
        self.assertNotIn("  sign:", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("\n    environment:", workflow)
        self.assertNotIn("evidence_attestation.py sign", workflow)
        self.assertNotIn("release_decision.py sign", workflow)
        self.assertNotIn("source-runs.json", workflow)
        self.assertIn(
            "path: artifacts/release-evidence-unsigned/release-inputs", workflow
        )
        self.assertNotIn("cp -R incoming", workflow)

    def test_promotion_gate_has_no_evidence_signing_key(self):
        workflow = (WORKFLOW_DIRECTORY / "promotion-gate.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("secrets.AURA_EVIDENCE", workflow)
        self.assertNotIn("AURA_EVIDENCE_ED25519_PRIVATE_KEY_B64", workflow)
        self.assertNotIn("evidence_attestation.py sign", workflow)
        self.assertNotIn("AURA_EVIDENCE_ATTESTATION_PATH", workflow)
        self.assertIn("evidence_attestation: `external_post_freeze`", workflow)

    def test_release_evidence_downloads_pinned_ids_and_hard_checks_archives(self):
        workflow = self.release_evidence_workflow()
        for invariant in (
            '"PROMOTION_ARTIFACT_ID_EXACT": promotion_artifact["id"]',
            '"APPLE_ARTIFACT_ID_EXACT": apple_artifact["id"]',
            "actions/artifacts/$PROMOTION_ARTIFACT_ID_EXACT/zip",
            "actions/artifacts/$APPLE_ARTIFACT_ID_EXACT/zip",
            '--expected-sha256 "$PROMOTION_ARTIFACT_SHA256_EXACT"',
            '--expected-sha256 "$APPLE_ARTIFACT_SHA256_EXACT"',
            '--expected-bytes "$PROMOTION_ARTIFACT_BYTES_EXACT"',
            '--expected-bytes "$APPLE_ARTIFACT_BYTES_EXACT"',
            "python3 ci/release_artifact_ingest.py",
            "--profile promotion",
            "--profile apple",
            "artifacts?per_page=100",
            "total_count != len(artifacts)",
            '--max-filesize "$PROMOTION_ARTIFACT_BYTES_EXACT"',
            '--max-filesize "$APPLE_ARTIFACT_BYTES_EXACT"',
        ):
            self.assertIn(invariant, workflow)
        self.assertNotIn("actions/download-artifact", workflow)
        download = workflow.split(
            "- name: Download exact immutable artifact archives", 1
        )[1].split("- name: Verify and ingest exact immutable artifacts", 1)[0]
        ingest = workflow.split(
            "- name: Verify and ingest exact immutable artifacts", 1
        )[1].split("- name: Build exact final evidence manifest", 1)[0]
        self.assertIn("GH_TOKEN: ${{ github.token }}", download)
        self.assertNotIn("GH_TOKEN", ingest)
        self.assertNotIn("Authorization: Bearer", ingest)

    def test_release_evidence_upload_inventory_is_exact_and_allowlisted(self):
        workflow = self.release_evidence_workflow()
        build_step = workflow.split("- name: Build exact final evidence manifest", 1)[1].split(
            "- name: Upload frozen unsigned evidence", 1
        )[0]
        self.assertIn("release_dossier.snapshot_fixed_tree", build_step)
        self.assertIn("if set(snapshots) != expected", build_step)
        self.assertIn("install -m 600", build_step)
        self.assertIn('test ! -e "$package"', build_step)
        self.assertNotIn("source-runs.json", build_step)
        self.assertIn(
            'release_dossier.SOURCE_PATHS["pilot_signoff_verification"]',
            build_step,
        )
        self.assertNotIn("cp -R", build_step)

    def test_pilot_signoff_ingest_is_manual_bounded_tokenless_verification(self):
        workflow = self.pilot_signoff_workflow()
        trigger = workflow.split("on:", 1)[1].split("jobs:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("pull_request:", trigger)
        self.assertNotIn("push:", trigger)
        for required_input in (
            "release_revision:",
            "bundle_base64:",
            "bundle_sha256:",
            "bundle_bytes:",
        ):
            self.assertIn(required_input, trigger)
        for invariant in (
            "declared_bytes > 32 * 1024",
            'hashlib.sha256(bundle).hexdigest() != declared_sha256',
            'test "$(git rev-parse HEAD)" = "$RELEASE_REVISION"',
            "AURA_PILOT_SIGNOFF_TRUST_POLICY_B64",
            "AURA_PILOT_SIGNOFF_TRUST_POLICY_SHA256",
            "python3 ci/pilot_signoff_verification.py verify",
            "--expected-trust-policy-sha256",
            "--release-revision \"$RELEASE_REVISION\"",
            "--require-pass",
            "pilot-review-signoff-bundle.json",
            "pilot-signoff-verification.json",
            "pilot-review-signoffs.json",
            "steps.publishability.outputs.ready == 'true'",
            "path: artifacts/pilot-signoff-ingest",
            "compression-level: 0",
        ):
            self.assertIn(invariant, workflow)
        verify = workflow.split(
            "- name: Verify every external pilot signoff offline", 1
        )[1].split("- name:", 1)[0]
        self.assertNotIn("GH_TOKEN", verify)
        self.assertNotIn("github.token", verify)
        self.assertNotIn("Authorization:", verify)
        self.assertNotIn("private", workflow.lower())
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn(" sign ", workflow)

    def test_promotion_pins_and_reverifies_exact_pilot_signoff_artifact(self):
        workflow = self.promotion_workflow()
        trigger = workflow.split("on:", 1)[1].split("env:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("pull_request:", trigger)
        for invariant in (
            "pilot_signoff_run_id:",
            "pilot_signoff_run_attempt:",
            "AURA_PILOT_SIGNOFF_WORKFLOW_ID",
            'test "$PILOT_SIGNOFF_RUN_ATTEMPT" = "1"',
            'run.get("workflow_id") != expected_workflow_id',
            'run.get("path") != ".github/workflows/pilot-signoff-ingest.yml"',
            'run.get("head_sha") != os.environ["GITHUB_SHA"]',
            'run.get("status") != "completed" or run.get("conclusion") != "success"',
            "total_count != 1",
            "len(artifacts) != 1",
            '"PILOT_SIGNOFF_ARTIFACT_ID_EXACT": artifact_id',
            '"PILOT_SIGNOFF_ARTIFACT_BYTES_EXACT": artifact_bytes',
            '"PILOT_SIGNOFF_ARTIFACT_SHA256_EXACT": digest.removeprefix("sha256:")',
            "actions/artifacts/$PILOT_SIGNOFF_ARTIFACT_ID_EXACT/zip",
            '--expected-sha256 "$PILOT_SIGNOFF_ARTIFACT_SHA256_EXACT"',
            '--expected-bytes "$PILOT_SIGNOFF_ARTIFACT_BYTES_EXACT"',
            "--profile pilot_signoff",
            "python3 ci/pilot_signoff_verification.py verify",
            "cmp -s \"$ingested/pilot-signoff-verification.json\"",
            "cmp -s \"$ingested/pilot-review-signoffs.json\"",
            'install -m 600 "$ingested/pilot-review-signoff-bundle.json"',
            'install -m 600 "$ingested/pilot-signoff-verification.json"',
            'install -m 600 "$ingested/pilot-review-signoffs.json"',
            '--review-signoffs "$AURA_PILOT_REVIEW_SIGNOFFS_PATH"',
            "if: ${{ inputs.target == 'release' }}",
        ):
            self.assertIn(invariant, workflow)
        download = workflow.split(
            "- name: Resolve exact hosted pilot signoff artifact", 1
        )[1].split("- name: Reverify and install hosted pilot signoffs offline", 1)[0]
        offline = workflow.split(
            "- name: Reverify and install hosted pilot signoffs offline", 1
        )[1].split("- name: Build", 1)[0]
        self.assertIn("GH_TOKEN: ${{ github.token }}", download)
        self.assertNotIn("GH_TOKEN", offline)
        self.assertNotIn("Authorization:", offline)
        self.assertNotIn("actions/download-artifact", workflow)

    def test_freeze_reverifies_and_carries_only_pilot_verification_leaf(self):
        workflow = self.release_evidence_workflow()
        reverify = workflow.split(
            "- name: Reverify frozen pilot signoffs against external trust policy", 1
        )[1].split("- name: Build exact final evidence manifest", 1)[0]
        for invariant in (
            "AURA_PILOT_SIGNOFF_TRUST_POLICY_B64",
            "AURA_PILOT_SIGNOFF_TRUST_POLICY_SHA256",
            "python3 ci/pilot_signoff_verification.py verify",
            "--bundle incoming/promotion/pilot-review-signoff-bundle.json",
            "--require-pass",
            "cmp -s incoming/promotion/pilot-signoff-verification.json",
            "cmp -s incoming/promotion/pilot-review-signoffs.json",
        ):
            self.assertIn(invariant, workflow)
        self.assertNotIn("GH_TOKEN", reverify)
        self.assertNotIn("Authorization:", reverify)
        build = workflow.split("- name: Build exact final evidence manifest", 1)[1]
        self.assertIn(
            "incoming/promotion/pilot-signoff-verification.json", build
        )
        self.assertNotIn(
            '"$package/release-inputs/pilot/pilot-review-signoff-bundle.json"',
            build,
        )
        self.assertNotIn(
            '"$package/release-inputs/pilot/pilot-review-signoffs.json"', build
        )


if __name__ == "__main__":
    unittest.main()
