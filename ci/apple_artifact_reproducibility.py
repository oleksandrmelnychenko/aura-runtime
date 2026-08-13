#!/usr/bin/env python3
"""Strict same-environment reproducibility gate for the Apple release artifact."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from ci.apple_artifact import (
        APPLE_ARTIFACT_FILE_LIMITS,
        ArtifactError,
        NON_BUILD_GOVERNANCE_PATHS,
        _lfs_source_expectations,
        _load_json,
        _read_bounded_regular,
        _source_index_entries,
        _source_paths,
        _verify_artifact_snapshot,
        snapshot_apple_artifact,
        source_tree_dirty,
        source_tree_identity,
    )
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    from apple_artifact import (  # type: ignore[no-redef]
        APPLE_ARTIFACT_FILE_LIMITS,
        ArtifactError,
        NON_BUILD_GOVERNANCE_PATHS,
        _lfs_source_expectations,
        _load_json,
        _read_bounded_regular,
        _source_index_entries,
        _source_paths,
        _verify_artifact_snapshot,
        snapshot_apple_artifact,
        source_tree_dirty,
        source_tree_identity,
    )


REPORT_SCHEMA = "aura.apple_artifact_reproducibility.v1"
FULL_GIT_SHA = re.compile(r"[0-9a-f]{40}")
EXPECTED_RUST_VERSION = "1.96.1"
EXPECTED_RUST_COMMIT = "31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd"
EXPECTED_LLVM_VERSION = "22.1.2"
EXPECTED_XCODE_VERSION = "26.2"
EXPECTED_XCODE_BUILD = "17C52"
EXPECTED_APPLE_SDK_VERSION = "26.2"
EXPECTED_APPLE_SDK_BUILD = "23C53"
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MINIMUM_BUILD_HEADROOM_BYTES = 16 * 1024 * 1024 * 1024
MAX_RELEASE_LINEAGE_COMMITS = 16

REPOSITORY_DIST_PREFIX = "dist/apple/"
REQUIRED_ARTIFACT_COMMIT_PATHS = frozenset(
    {
        "dist/apple/release-manifest.json",
        "dist/apple/runtime-artifact-descriptor.json",
        "dist/apple/runtime-artifact-identities.env",
    }
)
ALLOWED_ARTIFACT_COMMIT_PATHS = frozenset(
    REPOSITORY_DIST_PREFIX + path
    for path in APPLE_ARTIFACT_FILE_LIMITS
    if path != "execution-policy-trust-keyring.json"
)
ARCHIVE_PATHS = frozenset(
    REPOSITORY_DIST_PREFIX + path
    for path in APPLE_ARTIFACT_FILE_LIMITS
    if path.endswith(".a")
)


class ReproducibilityError(RuntimeError):
    """Raised when an Apple release-reproducibility invariant fails."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReproducibilityError(message)


def _command_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
            "GIT_CEILING_DIRECTORIES",
        } or key.startswith("GIT_CONFIG_"):
            environment.pop(key, None)
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = "/dev/null"
    environment.pop("GIT_EXTERNAL_DIFF", None)
    if extra:
        environment.update(extra)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment.pop("GIT_REPLACE_REF_BASE", None)
    return environment


def _run(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
) -> bytes:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment or _command_environment(),
        check=False,
        capture_output=True,
    )
    if len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES or len(result.stderr) > MAX_COMMAND_OUTPUT_BYTES:
        raise ReproducibilityError(
            f"command output exceeds its bound: {' '.join(arguments)}"
        )
    if result.returncode != 0:
        diagnostic = result.stderr.decode("utf-8", errors="replace").strip()
        raise ReproducibilityError(
            f"{' '.join(arguments)} failed: {diagnostic or 'no diagnostic'}"
        )
    return result.stdout


def _run_text(arguments: list[str], *, cwd: Path) -> str:
    return _run(arguments, cwd=cwd).decode("utf-8", errors="strict").strip()


def _full_clean_checkout(root: Path, expected_revision: str) -> None:
    _require(FULL_GIT_SHA.fullmatch(expected_revision) is not None, "invalid revision")
    grafts_path = Path(
        _run_text(["git", "rev-parse", "--git-path", "info/grafts"], cwd=root)
    )
    if not grafts_path.is_absolute():
        grafts_path = root / grafts_path
    if grafts_path.exists():
        _require(
            not _read_bounded_regular(
                grafts_path, MAX_COMMAND_OUTPUT_BYTES
            ).strip(),
            "Git graft metadata is forbidden for release provenance",
        )
    observed_revision = _run_text(["git", "rev-parse", "HEAD"], cwd=root)
    _require(observed_revision == expected_revision, "checkout revision changed")
    _source_index_entries(root)
    index_tree = _run_text(["git", "write-tree"], cwd=root)
    commit_tree = _run_text(
        ["git", "rev-parse", f"{expected_revision}^{{tree}}"], cwd=root
    )
    _require(index_tree == commit_tree, "Git index tree differs from the commit tree")

    for arguments, label in (
        (["git", "diff", "--quiet", "--no-ext-diff", "--ignore-submodules=none"], "worktree"),
        (
            [
                "git",
                "diff",
                "--cached",
                "--quiet",
                "--no-ext-diff",
                "--ignore-submodules=none",
            ],
            "index",
        ),
    ):
        result = subprocess.run(
            arguments,
            cwd=root,
            env=_command_environment(),
            check=False,
            capture_output=True,
        )
        _require(result.returncode == 0, f"Git {label} is not clean")
    untracked = _run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=root
    )
    _require(not untracked, "checkout contains untracked non-ignored files")


def _commit_changes(root: Path, previous: str, current: str) -> dict[str, str]:
    raw_diff = _run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-status",
            "-r",
            "-z",
            previous,
            current,
        ],
        cwd=root,
    )
    fields = raw_diff.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    _require(len(fields) % 2 == 0, "commit diff is malformed or contains a rename")
    changes: dict[str, str] = {}
    for index in range(0, len(fields), 2):
        status = fields[index].decode("ascii", errors="strict")
        path = fields[index + 1].decode("utf-8", errors="strict")
        _require(path not in changes, f"commit diff repeats a path: {path}")
        changes[path] = status
    return changes


def _artifact_commit_pair(
    root: Path, release_revision: str, source_revision: str
) -> str:
    """Validate H -> A -> optional governance-only suffix and return A."""

    _require(FULL_GIT_SHA.fullmatch(release_revision) is not None, "invalid release revision")
    _require(FULL_GIT_SHA.fullmatch(source_revision) is not None, "invalid source revision")
    _require(release_revision != source_revision, "release and source revisions must differ")

    reverse_lineage: list[str] = []
    current = release_revision
    for _ in range(MAX_RELEASE_LINEAGE_COMMITS):
        if current == source_revision:
            break
        parents = _run_text(
            ["git", "rev-list", "--parents", "-n", "1", current], cwd=root
        ).split()
        _require(
            len(parents) == 2 and parents[0] == current,
            "release lineage must be a bounded single-parent chain",
        )
        reverse_lineage.append(current)
        current = parents[1]
    _require(current == source_revision, "release revision does not descend linearly from source")
    lineage = list(reversed(reverse_lineage))
    _require(bool(lineage), "release lineage has no artifact commit")
    artifact_revision = lineage[0]

    artifact_changes = _commit_changes(root, source_revision, artifact_revision)
    for path, status in artifact_changes.items():
        _require(
            status == "M",
            f"artifact commit contains a non-modification: {status} {path}",
        )
        _require(
            path in ALLOWED_ARTIFACT_COMMIT_PATHS,
            f"artifact commit changes a non-generated path: {path}",
        )
    _require(
        REQUIRED_ARTIFACT_COMMIT_PATHS.issubset(artifact_changes),
        "artifact commit is missing required generated provenance documents",
    )

    previous = artifact_revision
    for governance_revision in lineage[1:]:
        governance_changes = _commit_changes(root, previous, governance_revision)
        _require(bool(governance_changes), "governance suffix commit is empty")
        for path, status in governance_changes.items():
            _require(
                status == "M" and path in NON_BUILD_GOVERNANCE_PATHS,
                "release suffix changes a non-governance path: "
                f"{status} {path}",
            )
        previous = governance_revision
    return artifact_revision


def _inventory_map(inventory: tuple[dict[str, Any], ...]) -> dict[str, dict[str, Any]]:
    mapped: dict[str, dict[str, Any]] = {}
    for item in inventory:
        path = item.get("path")
        _require(isinstance(path, str) and path not in mapped, "artifact inventory is malformed")
        mapped[path] = item
    _require(
        set(mapped) == set(APPLE_ARTIFACT_FILE_LIMITS),
        "artifact inventory path set differs from the release contract",
    )
    return mapped


def _require_equal_inventories(
    expected: tuple[dict[str, Any], ...],
    observed: tuple[dict[str, Any], ...],
    label: str,
) -> None:
    _require(expected == observed, f"{label} artifact inventory differs byte-for-byte")


def _bind_committed_archive_lfs(
    root: Path, inventory: tuple[dict[str, Any], ...]
) -> dict[str, dict[str, Any]]:
    expectations = _lfs_source_expectations(root, sorted(ARCHIVE_PATHS))
    _require(set(expectations) == set(ARCHIVE_PATHS), "every archive must be Git LFS governed")
    mapped = _inventory_map(inventory)
    result: dict[str, dict[str, Any]] = {}
    for repository_path in sorted(ARCHIVE_PATHS):
        relative_path = repository_path.removeprefix(REPOSITORY_DIST_PREFIX)
        expected_size, expected_sha256 = expectations[repository_path]
        item = mapped[relative_path]
        _require(
            item["size"] == expected_size and item["sha256"] == expected_sha256,
            f"committed archive does not match its Git LFS pointer: {repository_path}",
        )
        result[repository_path] = {
            "size": expected_size,
            "sha256": expected_sha256,
        }
    return result


def _source_identity(root: Path, expected_revision: str) -> dict[str, Any]:
    _full_clean_checkout(root, expected_revision)
    _require(not source_tree_dirty(root), "source checkout is not release-clean")
    digest, entry_count, content_bytes, identities = source_tree_identity(root)
    _require(
        len(identities) == entry_count,
        "source checkout contains a symbolic link or hard-linked file identity",
    )
    _full_clean_checkout(root, expected_revision)
    return {
        "source_tree_sha256": digest,
        "entry_count": entry_count,
        "content_bytes": content_bytes,
    }


def _toolchain_report(root: Path) -> dict[str, Any]:
    xcode_lines = _run_text(["xcodebuild", "-version"], cwd=root).splitlines()
    _require(
        xcode_lines == [
            f"Xcode {EXPECTED_XCODE_VERSION}",
            f"Build version {EXPECTED_XCODE_BUILD}",
        ],
        "Xcode version/build differs from the release contract",
    )
    sdk = _run_text(["xcrun", "--sdk", "iphoneos", "--show-sdk-version"], cwd=root)
    _require(sdk == EXPECTED_APPLE_SDK_VERSION, "Apple SDK differs from the release contract")
    sdk_build = _run_text(
        ["xcrun", "--sdk", "iphoneos", "--show-sdk-build-version"], cwd=root
    )
    _require(
        sdk_build == EXPECTED_APPLE_SDK_BUILD,
        "Apple SDK build differs from the release contract",
    )
    rustc = _run_text(["rustc", "-vV"], cwd=root)
    _require(f"release: {EXPECTED_RUST_VERSION}" in rustc, "Rust release differs")
    _require(f"commit-hash: {EXPECTED_RUST_COMMIT}" in rustc, "Rust commit differs")
    _require(f"LLVM version: {EXPECTED_LLVM_VERSION}" in rustc, "LLVM version differs")
    cargo = _run_text(["cargo", "--version"], cwd=root)
    _require(cargo.startswith(f"cargo {EXPECTED_RUST_VERSION} "), "Cargo version differs")
    selected_developer_dir = Path(
        os.environ.get("DEVELOPER_DIR")
        or _run_text(["xcode-select", "-p"], cwd=root)
    ).resolve(strict=True)
    resolved_xcodebuild = Path(
        _run_text(["xcrun", "--find", "xcodebuild"], cwd=root)
    ).resolve(strict=True)
    _require(
        resolved_xcodebuild.is_relative_to(selected_developer_dir),
        "xcrun selected xcodebuild outside the effective developer directory",
    )
    return {
        "xcode": xcode_lines,
        "iphoneos_sdk": sdk,
        "iphoneos_sdk_build": sdk_build,
        "effective_developer_dir": str(selected_developer_dir),
        "resolved_xcodebuild": str(resolved_xcodebuild),
        "global_xcode_select": _run_text(["xcode-select", "-p"], cwd=root),
        "rustc_verbose": rustc.splitlines(),
        "cargo": cargo,
        "git": _run_text(["git", "--version"], cwd=root),
        "git_lfs": _run_text(["git", "lfs", "version"], cwd=root),
        "python": _run_text([sys.executable, "--version"], cwd=root),
        "runner": {
            key: os.environ[key]
            for key in (
                "RUNNER_OS",
                "RUNNER_ARCH",
                "ImageOS",
                "ImageVersion",
                "GITHUB_RUN_ID",
                "GITHUB_RUN_ATTEMPT",
            )
            if key in os.environ
        },
    }


def _disk_preflight(root: Path, temporary_parent: Path) -> dict[str, int]:
    paths = _source_paths(root)
    expectations = _lfs_source_expectations(root, paths)
    lfs_bytes = sum(size for size, _ in expectations.values())
    required_free = lfs_bytes + MINIMUM_BUILD_HEADROOM_BYTES
    free = shutil.disk_usage(temporary_parent).free
    _require(
        free >= required_free,
        "insufficient free space for one sequential materialized source worktree and build",
    )
    return {
        "materialized_source_lfs_object_count": len(expectations),
        "materialized_source_lfs_bytes": lfs_bytes,
        "required_free_bytes": required_free,
        "observed_free_bytes": free,
    }


def _add_source_worktree(root: Path, source_revision: str, destination: Path) -> None:
    environment = _command_environment({"GIT_LFS_SKIP_SMUDGE": "1"})
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "worktree",
            "add",
            "--detach",
            str(destination),
            source_revision,
        ],
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise ReproducibilityError(
            "create detached source worktree failed: "
            + result.stderr.decode("utf-8", errors="replace").strip()
        )
    try:
        checkout = subprocess.run(
            ["git", "lfs", "checkout"],
            cwd=destination,
            env=_command_environment(),
            check=False,
            capture_output=True,
        )
        if checkout.returncode != 0:
            raise ReproducibilityError(
                "materialize source Git LFS objects failed: "
                + checkout.stderr.decode("utf-8", errors="replace").strip()
            )
    except BaseException:
        _remove_source_worktree(root, destination)
        raise


def _remove_source_worktree(root: Path, destination: Path) -> None:
    if destination.exists():
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(destination)],
            cwd=root,
            env=_command_environment(),
            check=False,
            capture_output=True,
        )
    subprocess.run(
        ["git", "worktree", "prune"],
        cwd=root,
        env=_command_environment(),
        check=False,
        capture_output=True,
    )


def _build_apple_artifact(source_root: Path, output: Path) -> None:
    environment = _command_environment()
    for key in (
        "ALLOW_DIRTY_SOURCE",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "AURA_LLVM_NM",
        "AURA_LLVM_STRIP",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "PROFILE": "release",
            "AURA_AGENT_ONNX": "0",
            "MINIMUM_IOS_VERSION": "18.0",
            "AURA_APPLE_DIST_DIR": str(output),
            "AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH": str(
                source_root / "dist/apple/execution-policy-trust-keyring.json"
            ),
            "CARGO_BUILD_JOBS": os.environ.get("CARGO_BUILD_JOBS", "10"),
            "CARGO_NET_OFFLINE": "true",
        }
    )
    result = subprocess.run(
        ["bash", "scripts/release/build-apple-xcframework.sh"],
        cwd=source_root,
        env=environment,
        check=False,
    )
    _require(result.returncode == 0, "Apple artifact build failed")


def _copy_verified_snapshot(snapshot: Path, output: Path) -> None:
    _require(not output.exists() and not output.is_symlink(), "verified output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    parent_metadata = output.parent.lstat()
    _require(stat.S_ISDIR(parent_metadata.st_mode), "verified output parent is not a directory")
    staging = Path(tempfile.mkdtemp(prefix=".apple-verified.", dir=output.parent))
    try:
        for relative_path in sorted(APPLE_ARTIFACT_FILE_LIMITS):
            source = snapshot / relative_path
            destination = staging / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination, follow_symlinks=False)
            source_mode = source.stat().st_mode
            destination.chmod(0o700 if source_mode & stat.S_IXUSR else 0o600)
        os.replace(staging, output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _write_report(path: Path, report: dict[str, Any]) -> None:
    encoded = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    _require(len(encoded) <= MAX_COMMAND_OUTPUT_BYTES, "reproducibility report is too large")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(temporary_descriptor, "wb") as file:
            file.write(encoded)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def verify_reproducibility(
    root: Path,
    *,
    output: Path,
    temporary_parent: Path,
    verified_dist_output: Path,
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    temporary_parent = temporary_parent.resolve(strict=True)
    _require(temporary_parent.is_dir(), "temporary parent must be a directory")
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    _require(event_name != "pull_request", "release reproducibility proof is forbidden on PR")

    release_revision = _run_text(["git", "rev-parse", "HEAD"], cwd=root)
    github_sha = os.environ.get("GITHUB_SHA")
    if github_sha:
        _require(github_sha == release_revision, "checkout HEAD differs from GITHUB_SHA")
    _full_clean_checkout(root, release_revision)
    toolchain = _toolchain_report(root)
    disk = _disk_preflight(root, temporary_parent)

    committed_dist = root / "dist/apple"
    with snapshot_apple_artifact(committed_dist) as (committed_snapshot, committed_inventory):
        manifest = _load_json(committed_snapshot / "release-manifest.json")
        source_revision = manifest.get("source_revision")
        _require(isinstance(source_revision, str), "release manifest source revision is absent")
        artifact_revision = _artifact_commit_pair(
            root, release_revision, source_revision
        )
        archive_lfs = _bind_committed_archive_lfs(root, committed_inventory)

        build_inventories: list[tuple[dict[str, Any], ...]] = []
        source_identities: list[dict[str, Any]] = []
        committed_verification: dict[str, Any] | None = None
        for build_number in (1, 2):
            with tempfile.TemporaryDirectory(
                prefix=f"aura-apple-repro-{build_number}.", dir=temporary_parent
            ) as raw_directory:
                iteration_root = Path(raw_directory)
                source_root = iteration_root / "source"
                build_output = iteration_root / "output"
                _add_source_worktree(root, source_revision, source_root)
                try:
                    before = _source_identity(source_root, source_revision)
                    _require(
                        before["source_tree_sha256"] == manifest.get("source_tree_sha256"),
                        "materialized source worktree digest differs from the manifest",
                    )
                    if build_number == 1:
                        committed_verification = _verify_artifact_snapshot(
                            source_root,
                            committed_snapshot,
                            require_clean_source=True,
                        )
                    _build_apple_artifact(source_root, build_output)
                    with snapshot_apple_artifact(build_output) as (
                        build_snapshot,
                        build_inventory,
                    ):
                        _verify_artifact_snapshot(
                            source_root,
                            build_snapshot,
                            require_clean_source=True,
                        )
                    after = _source_identity(source_root, source_revision)
                    _require(before == after, "source checkout changed during Apple build")
                    _require_equal_inventories(
                        committed_inventory,
                        build_inventory,
                        f"build {build_number}",
                    )
                    source_identities.append(before)
                    build_inventories.append(build_inventory)
                finally:
                    _remove_source_worktree(root, source_root)

        _require(committed_verification is not None, "committed artifact was not verified")
        _require_equal_inventories(
            build_inventories[0], build_inventories[1], "two-build comparison"
        )
        _full_clean_checkout(root, release_revision)
        _copy_verified_snapshot(committed_snapshot, verified_dist_output)

    with snapshot_apple_artifact(verified_dist_output) as (_, retained_inventory):
        _require_equal_inventories(
            committed_inventory, retained_inventory, "retained verified candidate"
        )

    return {
        "schema_version": REPORT_SCHEMA,
        "status": "pass",
        "claim": "same_environment_deterministic_rebuild",
        "independent_reproduction_proven": False,
        "compiler_trust_proven": False,
        "candidate_blind_build_proven": False,
        "hermetic_build_proven": False,
        "trusted_source_and_build_scripts_assumed": True,
        "release_revision": release_revision,
        "artifact_revision": artifact_revision,
        "source_revision": source_revision,
        "source_tree_sha256": manifest["source_tree_sha256"],
        "artifact_commit_policy": {
            "direct_single_parent": True,
            "generated_only_diff": True,
            "governance_only_release_suffix": True,
        },
        "committed_artifact_verification": committed_verification,
        "committed_archive_lfs": archive_lfs,
        "artifact_inventory": list(committed_inventory),
        "build_count": 2,
        "source_identities": source_identities,
        "all_three_inventories_equal": True,
        "verified_dist_output": str(verified_dist_output),
        "disk_preflight": disk,
        "toolchain": toolchain,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify the checked-in Apple artifact and rebuild its exact source twice."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)
    verify.add_argument(
        "--temporary-parent", type=Path, default=Path(tempfile.gettempdir())
    )
    verify.add_argument("--verified-dist-output", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    output = arguments.output
    verified_dist = arguments.verified_dist_output
    if verified_dist is None:
        verified_dist = output.parent / "apple-verified-dist"
    try:
        report = verify_reproducibility(
            arguments.root,
            output=output,
            temporary_parent=arguments.temporary_parent,
            verified_dist_output=verified_dist,
        )
        _write_report(output, report)
        print(f"Apple reproducibility report written to {output} (status=pass)")
        return 0
    except (ArtifactError, ReproducibilityError, OSError, UnicodeError, ValueError) as error:
        try:
            _write_report(
                output,
                {
                    "schema_version": REPORT_SCHEMA,
                    "status": "fail",
                    "error": str(error),
                },
            )
        except (OSError, ReproducibilityError):
            pass
        print(f"Apple reproducibility verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
