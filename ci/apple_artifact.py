#!/usr/bin/env python3
"""Build-source identity and verification helpers for Apple release artifacts."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator


RELEASE_MANIFEST_SCHEMA_VERSION = 5
RUNTIME_DESCRIPTOR_SCHEMA_VERSION = 3
VERIFICATION_REPORT_SCHEMA = "aura.apple_artifact_verification.v1"
SOURCE_TREE_DIGEST_DOMAIN = b"aura.build-source-tree.v2\0"
LFS_POINTER_PATTERN = re.compile(
    rb"version https://git-lfs.github.com/spec/v1\n"
    rb"oid sha256:([0-9a-f]{64})\n"
    rb"size (0|[1-9][0-9]*)\n"
)
MAX_LFS_POINTER_BYTES = 1024
MAX_RELEASE_JSON_BYTES = 1024 * 1024
MAX_APPLE_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_APPLE_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
GIT_LFS_FILTER_CONFIG = (
    ("filter.lfs.process", "git-lfs filter-process"),
    ("filter.lfs.smudge", "git-lfs smudge -- %f"),
    ("filter.lfs.clean", "git-lfs clean -- %f"),
    ("filter.lfs.required", "true"),
)

GENERATED_SOURCE_PATHS = {
    "dist/apple/release-manifest.json",
    "dist/apple/runtime-artifact-descriptor.json",
    "dist/apple/runtime-artifact-identities.env",
}
GENERATED_SOURCE_PREFIXES = ("dist/apple/AuraAgentFFI.xcframework/",)
NON_BUILD_GOVERNANCE_PATHS = {
    "crates/aura-core/data/refactor_baseline_v1.json",
    "docs/refactor-diff-approvals.json",
}

EXPECTED_TARGET_TRIPLES = [
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "x86_64-apple-ios",
    "aarch64-apple-ios-macabi",
    "x86_64-apple-ios-macabi",
]
EXPECTED_SLICES = {
    "ios-arm64": {
        "library": "libaura_agent_ffi.a",
        "architectures": {"arm64"},
        "platform": "ios",
        "variant": None,
        "mach_o_platform": 2,
    },
    "ios-arm64_x86_64-simulator": {
        "library": "libaura_agent_ffi_ios_sim.a",
        "architectures": {"arm64", "x86_64"},
        "platform": "ios",
        "variant": "simulator",
        "mach_o_platform": 7,
    },
    "ios-arm64_x86_64-maccatalyst": {
        "library": "libaura_agent_ffi_maccatalyst.a",
        "architectures": {"arm64", "x86_64"},
        "platform": "ios",
        "variant": "maccatalyst",
        "mach_o_platform": 6,
    },
}
RELEASE_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "source_revision",
        "source_tree_dirty",
        "source_tree_sha256",
        "shippable",
        "cargo_profile",
        "cargo_locked",
        "cargo_features",
        "runtime_release_version",
        "wire_package",
        "wire_major_version",
        "state_schema_version",
        "ffi_contract_version",
        "minimum_ios_version",
        "target_triples",
        "aura_ffi_header_sha256",
        "runtime_capabilities_sha256",
        "runtime_artifact_descriptor_sha256",
        "runtime_artifact_identities_env_sha256",
        "model_manifest_sha256",
        "execution_policy_trust_keyring_sha256",
        "xcframework_info_plist_sha256",
        "binary_sha256",
        "model_bundle_included",
    }
)
RUNTIME_DESCRIPTOR_FIELDS = frozenset(
    {
        "schema_version",
        "source_revision",
        "source_tree_dirty",
        "source_tree_sha256",
        "shippable",
        "cargo_profile",
        "cargo_features",
        "runtime_release_version",
        "wire_package",
        "wire_major_version",
        "state_schema_version",
        "ffi_contract_version",
        "aura_ffi_header_sha256",
        "runtime_capabilities_sha256",
        "model_manifest_sha256",
        "execution_policy_trust_keyring_sha256",
    }
)

APPLE_ARTIFACT_FILE_LIMITS = {
    "AuraAgentFFI.xcframework/Info.plist": 256 * 1024,
    "AuraAgentFFI.xcframework/ios-arm64/Headers/aura_ffi.h": 1024 * 1024,
    "AuraAgentFFI.xcframework/ios-arm64/libaura_agent_ffi.a": MAX_APPLE_ARCHIVE_BYTES,
    "AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/Headers/aura_ffi.h": 1024
    * 1024,
    "AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/libaura_agent_ffi_maccatalyst.a": MAX_APPLE_ARCHIVE_BYTES,
    "AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/Headers/aura_ffi.h": 1024
    * 1024,
    "AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/libaura_agent_ffi_ios_sim.a": MAX_APPLE_ARCHIVE_BYTES,
    "execution-policy-trust-keyring.json": MAX_RELEASE_JSON_BYTES,
    "release-manifest.json": MAX_RELEASE_JSON_BYTES,
    "runtime-artifact-descriptor.json": MAX_RELEASE_JSON_BYTES,
    "runtime-artifact-identities.env": 64 * 1024,
}


class ArtifactError(RuntimeError):
    """Raised when release provenance or packaged content is inconsistent."""


def _git_environment() -> dict[str, str]:
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
    environment["GIT_CONFIG_COUNT"] = str(len(GIT_LFS_FILTER_CONFIG))
    for index, (key, value) in enumerate(GIT_LFS_FILTER_CONFIG):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment.pop("GIT_REPLACE_REF_BASE", None)
    environment.pop("GIT_EXTERNAL_DIFF", None)
    return environment


def _run(
    args: list[str],
    *,
    cwd: Path,
    text: bool = False,
) -> str | bytes:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=_git_environment() if args and args[0] == "git" else None,
        check=False,
        capture_output=True,
        text=text,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() if text else result.stderr.decode().strip()
        raise ArtifactError(f"{' '.join(args)} failed: {stderr}")
    return result.stdout


def _git_paths(root: Path, args: list[str]) -> set[str]:
    output = _run(["git", *args, "-z"], cwd=root)
    assert isinstance(output, bytes)
    return {
        item.decode("utf-8", errors="surrogateescape")
        for item in output.split(b"\0")
        if item
    }


def _is_build_source_excluded_path(relative_path: str) -> bool:
    return (
        relative_path in GENERATED_SOURCE_PATHS
        or relative_path in NON_BUILD_GOVERNANCE_PATHS
        or relative_path.startswith(GENERATED_SOURCE_PREFIXES)
    )


def _source_paths(root: Path) -> list[str]:
    paths = _git_paths(
        root,
        ["ls-files", "--cached", "--others", "--exclude-standard"],
    )
    return sorted(path for path in paths if not _is_build_source_excluded_path(path))


def _source_index_entries(root: Path) -> dict[str, tuple[str, str]]:
    """Return a normal stage-0 Git index without hidden or sparse entries."""

    grafts_output = _run(
        ["git", "rev-parse", "--git-path", "info/grafts"], cwd=root, text=True
    )
    assert isinstance(grafts_output, str)
    grafts = Path(grafts_output.strip())
    if not grafts.is_absolute():
        grafts = root / grafts
    if grafts.exists() and _read_bounded_regular(
        grafts, MAX_RELEASE_JSON_BYTES
    ).strip():
        raise ArtifactError("Git graft metadata is forbidden for release source")

    sparse = subprocess.run(
        ["git", "config", "--bool", "--get", "core.sparseCheckout"],
        cwd=root,
        env=_git_environment(),
        check=False,
        capture_output=True,
        text=True,
    )
    if sparse.returncode not in {0, 1}:
        raise ArtifactError(f"read Git sparse-checkout config: {sparse.stderr.strip()}")
    if sparse.returncode == 0 and sparse.stdout.strip() == "true":
        raise ArtifactError("sparse checkout is forbidden for release source")

    sparse_path_output = _run(
        ["git", "rev-parse", "--git-path", "info/sparse-checkout"],
        cwd=root,
        text=True,
    )
    assert isinstance(sparse_path_output, str)
    sparse_path = Path(sparse_path_output.strip())
    if not sparse_path.is_absolute():
        sparse_path = root / sparse_path
    if sparse_path.exists() and _read_bounded_regular(
        sparse_path, MAX_RELEASE_JSON_BYTES
    ).strip():
        raise ArtifactError("Git sparse-checkout patterns must be absent or empty")

    output = _run(["git", "ls-files", "--stage", "-v", "-z"], cwd=root)
    assert isinstance(output, bytes)
    entries: dict[str, tuple[str, str]] = {}
    for raw_record in output.split(b"\0"):
        if not raw_record:
            continue
        try:
            prefix, encoded_path = raw_record.split(b"\t", 1)
            tag, mode, object_id, stage = prefix.decode("ascii").split(" ")
        except (UnicodeDecodeError, ValueError, IndexError) as error:
            raise ArtifactError("git ls-files returned malformed index metadata") from error
        relative_path = encoded_path.decode("utf-8", errors="surrogateescape")
        if tag != "H":
            raise ArtifactError(
                "Git index entry has a hidden, sparse, or exceptional state: "
                f"{relative_path} ({tag})"
            )
        if stage != "0" or mode not in {"100644", "100755"}:
            raise ArtifactError(
                f"Git source must be a stage-0 regular file: {relative_path}"
            )
        if relative_path in entries:
            raise ArtifactError(f"duplicate Git index path: {relative_path}")
        entries[relative_path] = (mode, object_id)
    if not entries:
        raise ArtifactError("Git source index is empty")
    return entries


def _lfs_source_expectations(root: Path, paths: list[str]) -> dict[str, tuple[int, str]]:
    """Return exact Git-index LFS size/digest claims for build-source paths.

    The source-tree commitment hashes materialized build inputs, not Git LFS
    pointer text. Resolve the expected objects from the Git index without
    trusting the working tree or requiring the ``git-lfs`` executable.
    """

    info_attributes_output = _run(
        ["git", "rev-parse", "--git-path", "info/attributes"], cwd=root, text=True
    )
    assert isinstance(info_attributes_output, str)
    info_attributes = Path(info_attributes_output.strip())
    if not info_attributes.is_absolute():
        info_attributes = root / info_attributes
    if info_attributes.exists() and _read_bounded_regular(
        info_attributes, MAX_RELEASE_JSON_BYTES
    ).strip():
        raise ArtifactError("Git info/attributes must be absent or empty")

    encoded_paths = b"".join(
        path.encode("utf-8", errors="surrogateescape") + b"\0" for path in paths
    )
    git_environment = _git_environment()
    git_environment["GIT_ATTR_NOSYSTEM"] = "1"
    attributes = subprocess.run(
        [
            "git",
            "-c",
            "core.attributesFile=/dev/null",
            "check-attr",
            "--cached",
            "--stdin",
            "-z",
            "filter",
        ],
        cwd=root,
        check=False,
        env=git_environment,
        input=encoded_paths,
        capture_output=True,
    )
    if attributes.returncode != 0:
        raise ArtifactError(
            "git check-attr failed: "
            + attributes.stderr.decode("utf-8", errors="replace").strip()
        )
    attribute_fields = attributes.stdout.split(b"\0")
    if attribute_fields and attribute_fields[-1] == b"":
        attribute_fields.pop()
    if len(attribute_fields) != len(paths) * 3:
        raise ArtifactError("git check-attr returned malformed LFS metadata")
    lfs_paths = set()
    for index in range(0, len(attribute_fields), 3):
        relative_path = attribute_fields[index].decode(
            "utf-8", errors="surrogateescape"
        )
        if attribute_fields[index + 1] != b"filter":
            raise ArtifactError("git check-attr returned an unexpected attribute")
        filter_value = attribute_fields[index + 2]
        if filter_value == b"lfs":
            lfs_paths.add(relative_path)
        elif filter_value != b"unspecified":
            raise ArtifactError(
                f"unsupported Git content filter for build source: {relative_path}"
            )
    if not lfs_paths:
        return {}

    staged = _run(["git", "ls-files", "--stage", "-z"], cwd=root)
    assert isinstance(staged, bytes)
    index_blobs: dict[str, str] = {}
    for record in staged.split(b"\0"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split(" ")
        except (UnicodeDecodeError, ValueError) as error:
            raise ArtifactError("git ls-files returned malformed index metadata") from error
        relative_path = encoded_path.decode("utf-8", errors="surrogateescape")
        if relative_path not in lfs_paths:
            continue
        if stage != "0" or mode not in {"100644", "100755"}:
            raise ArtifactError(
                f"Git LFS source must be a stage-0 regular file: {relative_path}"
            )
        index_blobs[relative_path] = object_id

    expectations: dict[str, tuple[int, str]] = {}
    for relative_path in sorted(lfs_paths):
        object_id = index_blobs.get(relative_path)
        if object_id is None:
            raise ArtifactError(
                f"Git LFS build source is not tracked in the index: {relative_path}"
            )
        encoded_size = _run(["git", "cat-file", "-s", object_id], cwd=root, text=True)
        assert isinstance(encoded_size, str)
        try:
            pointer_size = int(encoded_size.strip())
        except ValueError as error:
            raise ArtifactError(
                f"Git LFS pointer size is malformed: {relative_path}"
            ) from error
        if pointer_size <= 0 or pointer_size > MAX_LFS_POINTER_BYTES:
            raise ArtifactError(
                f"Git index does not contain a bounded LFS pointer: {relative_path}"
            )
        pointer = _run(["git", "cat-file", "blob", object_id], cwd=root)
        assert isinstance(pointer, bytes)
        match = LFS_POINTER_PATTERN.fullmatch(pointer)
        if match is None:
            raise ArtifactError(
                f"Git index contains a malformed LFS pointer: {relative_path}"
            )
        expected_digest = match.group(1).decode("ascii")
        expected_size = int(match.group(2))
        expectations[relative_path] = (expected_size, expected_digest)
    return expectations


def _frame(hasher: Any, payload: bytes) -> None:
    hasher.update(len(payload).to_bytes(8, byteorder="big"))
    hasher.update(payload)


def _source_entry_metadata(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def source_tree_identity(
    root: Path,
) -> tuple[str, int, int, frozenset[tuple[int, int]]]:
    """Hash build source and return digest, entry count, and content bytes.

    Regular files are streamed from one non-following descriptor. Symbolic
    links bind their target text. Missing tracked paths retain the historical
    ``D`` framing and contribute zero content bytes.
    """

    root = root.resolve()
    index_entries = _source_index_entries(root)
    paths = _source_paths(root)
    if not paths:
        raise ArtifactError(f"no Git source paths found under {root}")
    lfs_expectations = _lfs_source_expectations(root, paths)

    hasher = hashlib.sha256()
    hasher.update(SOURCE_TREE_DIGEST_DOMAIN)
    total_content_bytes = 0
    regular_file_identities = set()
    for relative_path in paths:
        path = root / relative_path
        lfs_expectation = lfs_expectations.get(relative_path)
        _frame(hasher, relative_path.encode("utf-8", errors="surrogateescape"))

        try:
            initial_metadata = path.lstat()
        except FileNotFoundError:
            kind = "tracked" if relative_path in index_entries else "untracked"
            raise ArtifactError(
                f"{kind} build source disappeared before hashing: {relative_path}"
            )

        if stat.S_ISLNK(initial_metadata.st_mode):
            if lfs_expectation is not None:
                raise ArtifactError(
                    f"Git LFS build source is not a regular file: {relative_path}"
                )
            target = os.readlink(path).encode("utf-8", errors="surrogateescape")
            final_metadata = path.lstat()
            if _source_entry_metadata(initial_metadata) != _source_entry_metadata(
                final_metadata
            ):
                raise ArtifactError(f"source-tree link changed while hashing: {relative_path}")
            hasher.update(b"L")
            _frame(hasher, target)
            total_content_bytes += len(target)
        elif stat.S_ISREG(initial_metadata.st_mode):
            if initial_metadata.st_nlink != 1:
                raise ArtifactError(
                    f"source-tree file must not be hard-linked: {relative_path}"
                )
            flags = os.O_RDONLY
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(path, flags)
            except OSError as error:
                raise ArtifactError(
                    f"source-tree file cannot be opened safely: {relative_path}"
                ) from error
            try:
                opened_metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened_metadata.st_mode)
                    or opened_metadata.st_nlink != 1
                    or _source_entry_metadata(initial_metadata)
                    != _source_entry_metadata(opened_metadata)
                ):
                    raise ArtifactError(
                        f"source-tree file changed before hashing: {relative_path}"
                    )
                regular_file_identities.add(
                    (opened_metadata.st_dev, opened_metadata.st_ino)
                )
                expected_size = opened_metadata.st_size
                if expected_size < 0:
                    raise ArtifactError(f"source-tree file size is invalid: {relative_path}")
                lfs_hasher = None
                if lfs_expectation is not None:
                    lfs_expected_size, _ = lfs_expectation
                    if expected_size != lfs_expected_size:
                        raise ArtifactError(
                            "Git LFS object is not materialized to its declared size: "
                            f"{relative_path}"
                        )
                    lfs_hasher = hashlib.sha256()
                hasher.update(b"F")
                executable = bool(opened_metadata.st_mode & stat.S_IXUSR)
                hasher.update(b"X" if executable else b"-")
                hasher.update(expected_size.to_bytes(8, byteorder="big"))
                observed_size = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    observed_size += len(chunk)
                    if observed_size > expected_size:
                        raise ArtifactError(
                            f"source-tree file grew while hashing: {relative_path}"
                        )
                    hasher.update(chunk)
                    if lfs_hasher is not None:
                        lfs_hasher.update(chunk)
                final_metadata = os.fstat(descriptor)
                if (
                    observed_size != expected_size
                    or _source_entry_metadata(opened_metadata)
                    != _source_entry_metadata(final_metadata)
                ):
                    raise ArtifactError(
                        f"source-tree file changed while hashing: {relative_path}"
                    )
                if lfs_hasher is not None:
                    _, lfs_expected_digest = lfs_expectation
                    if lfs_hasher.hexdigest() != lfs_expected_digest:
                        raise ArtifactError(
                            "Git LFS object digest does not match its index pointer: "
                            f"{relative_path}"
                        )
                total_content_bytes += observed_size
            finally:
                os.close(descriptor)
        else:
            raise ArtifactError(f"unsupported source-tree entry: {relative_path}")

    return (
        hasher.hexdigest(),
        len(paths),
        total_content_bytes,
        frozenset(regular_file_identities),
    )


def source_tree_digest(root: Path) -> str:
    """Hash build-relevant source without generated or self-referential evidence."""

    digest, _, _, _ = source_tree_identity(root)
    return digest


def source_tree_dirty(root: Path) -> bool:
    """Return whether reviewable source differs from HEAD/index."""

    root = root.resolve()
    changed = set()
    changed.update(_git_paths(root, ["diff", "--name-only"]))
    changed.update(_git_paths(root, ["diff", "--cached", "--name-only"]))
    changed.update(
        _git_paths(root, ["ls-files", "--others", "--exclude-standard"])
    )
    if any(not _is_build_source_excluded_path(path) for path in changed):
        return True
    _source_index_entries(root)
    return False


def _source_revision_is_ancestor(
    root: Path,
    source_revision: str,
    current_revision: str,
) -> bool:
    """Allow an artifact-only commit to follow the exact source revision."""

    result = subprocess.run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            source_revision,
            current_revision,
        ],
        cwd=root,
        env=_git_environment(),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise ArtifactError(
        "git merge-base --is-ancestor failed: "
        f"{result.stderr.strip() or 'unknown Git error'}"
    )


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _read_bounded_regular(path: Path, maximum_bytes: int) -> bytes:
    try:
        initial_metadata = path.lstat()
    except OSError as error:
        raise ArtifactError(f"read file metadata {path}: {error}") from error
    if not stat.S_ISREG(initial_metadata.st_mode):
        raise ArtifactError(f"expected a regular non-symlink file: {path}")
    if initial_metadata.st_size < 0 or initial_metadata.st_size > maximum_bytes:
        raise ArtifactError(f"file exceeds its byte bound: {path}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ArtifactError(f"open file safely {path}: {error}") from error
    try:
        opened_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_metadata.st_mode)
            or _source_entry_metadata(initial_metadata)
            != _source_entry_metadata(opened_metadata)
        ):
            raise ArtifactError(f"file changed before it was read: {path}")
        chunks = []
        observed_size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1))
            if not chunk:
                break
            observed_size += len(chunk)
            if observed_size > maximum_bytes or observed_size > opened_metadata.st_size:
                raise ArtifactError(f"file exceeded its byte bound while read: {path}")
            chunks.append(chunk)
        final_metadata = os.fstat(descriptor)
        if (
            observed_size != opened_metadata.st_size
            or _source_entry_metadata(opened_metadata)
            != _source_entry_metadata(final_metadata)
        ):
            raise ArtifactError(f"file changed while it was read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _artifact_directory_children() -> dict[str, frozenset[str]]:
    children: dict[str, set[str]] = {"": set()}
    for relative_path in APPLE_ARTIFACT_FILE_LIMITS:
        components = relative_path.split("/")
        parent = ""
        for component in components[:-1]:
            children.setdefault(parent, set()).add(component)
            parent = f"{parent}/{component}".lstrip("/")
            children.setdefault(parent, set())
        children[parent].add(components[-1])
    return {path: frozenset(names) for path, names in children.items()}


APPLE_ARTIFACT_DIRECTORY_CHILDREN = _artifact_directory_children()


@contextlib.contextmanager
def snapshot_apple_artifact(
    dist_dir: Path,
) -> Iterator[tuple[Path, tuple[dict[str, Any], ...]]]:
    """Copy the exact bounded Apple artifact tree from stable descriptors.

    The verifier invokes external binary tools after hashing. A private snapshot
    prevents a mutable or shared output directory from changing a file between
    those operations. Directory enumeration is exact and all traversal after the
    root open is relative to non-following directory descriptors.
    """

    if not dist_dir.is_absolute():
        dist_dir = Path.cwd() / dist_dir
    dist_dir = Path(os.path.abspath(os.fspath(dist_dir)))
    try:
        initial_root = dist_dir.lstat()
    except OSError as error:
        raise ArtifactError(f"read Apple artifact directory metadata: {error}") from error
    if not stat.S_ISDIR(initial_root.st_mode):
        raise ArtifactError("Apple artifact root must be a non-symlink directory")

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_descriptor = os.open(dist_dir, directory_flags)
    except OSError as error:
        raise ArtifactError(f"open Apple artifact directory safely: {error}") from error

    try:
        opened_root = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or _source_entry_metadata(initial_root)
            != _source_entry_metadata(opened_root)
        ):
            raise ArtifactError("Apple artifact root changed before snapshot")

        with tempfile.TemporaryDirectory(prefix="aura-apple-artifact-snapshot.") as raw:
            snapshot_root = Path(raw) / "dist"
            snapshot_root.mkdir(mode=0o700)
            identities: set[tuple[int, int]] = set()
            inventory: list[dict[str, Any]] = []
            total_bytes = 0

            def copy_directory(
                source_descriptor: int,
                relative_directory: str,
                destination_directory: Path,
            ) -> None:
                nonlocal total_bytes
                try:
                    observed_children = frozenset(os.listdir(source_descriptor))
                except OSError as error:
                    raise ArtifactError(
                        f"enumerate Apple artifact directory {relative_directory or '.'}: "
                        f"{error}"
                    ) from error
                expected_children = APPLE_ARTIFACT_DIRECTORY_CHILDREN[relative_directory]
                if observed_children != expected_children:
                    raise ArtifactError(
                        "Apple artifact inventory differs at "
                        f"{relative_directory or '.'}: "
                        f"missing={sorted(expected_children - observed_children)} "
                        f"unexpected={sorted(observed_children - expected_children)}"
                    )

                for name in sorted(expected_children):
                    relative_path = f"{relative_directory}/{name}".lstrip("/")
                    try:
                        initial = os.stat(
                            name, dir_fd=source_descriptor, follow_symlinks=False
                        )
                    except OSError as error:
                        raise ArtifactError(
                            f"read Apple artifact metadata {relative_path}: {error}"
                        ) from error

                    destination = destination_directory / name
                    if relative_path in APPLE_ARTIFACT_DIRECTORY_CHILDREN:
                        if not stat.S_ISDIR(initial.st_mode):
                            raise ArtifactError(
                                f"Apple artifact directory is not regular: {relative_path}"
                            )
                        try:
                            child_descriptor = os.open(
                                name, directory_flags, dir_fd=source_descriptor
                            )
                        except OSError as error:
                            raise ArtifactError(
                                f"open Apple artifact directory {relative_path}: {error}"
                            ) from error
                        try:
                            opened = os.fstat(child_descriptor)
                            if (
                                not stat.S_ISDIR(opened.st_mode)
                                or _source_entry_metadata(initial)
                                != _source_entry_metadata(opened)
                            ):
                                raise ArtifactError(
                                    f"Apple artifact directory changed: {relative_path}"
                                )
                            destination.mkdir(mode=0o700)
                            copy_directory(
                                child_descriptor, relative_path, destination
                            )
                            final = os.fstat(child_descriptor)
                            if _source_entry_metadata(opened) != _source_entry_metadata(final):
                                raise ArtifactError(
                                    f"Apple artifact directory changed: {relative_path}"
                                )
                        finally:
                            os.close(child_descriptor)
                        continue

                    if not stat.S_ISREG(initial.st_mode):
                        raise ArtifactError(
                            f"Apple artifact file must be regular: {relative_path}"
                        )
                    if initial.st_nlink != 1:
                        raise ArtifactError(
                            f"Apple artifact file must not be hard-linked: {relative_path}"
                        )
                    maximum_bytes = APPLE_ARTIFACT_FILE_LIMITS[relative_path]
                    if initial.st_size < 0 or initial.st_size > maximum_bytes:
                        raise ArtifactError(
                            f"Apple artifact file exceeds its bound: {relative_path}"
                        )
                    identity = (initial.st_dev, initial.st_ino)
                    if identity in identities:
                        raise ArtifactError(
                            f"Apple artifact files share an inode: {relative_path}"
                        )
                    identities.add(identity)

                    file_flags = (
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                    )
                    try:
                        source_file = os.open(
                            name, file_flags, dir_fd=source_descriptor
                        )
                    except OSError as error:
                        raise ArtifactError(
                            f"open Apple artifact file {relative_path}: {error}"
                        ) from error
                    try:
                        opened = os.fstat(source_file)
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or opened.st_nlink != 1
                            or _source_entry_metadata(initial)
                            != _source_entry_metadata(opened)
                        ):
                            raise ArtifactError(
                                f"Apple artifact file changed before snapshot: {relative_path}"
                            )
                        total_bytes += opened.st_size
                        if total_bytes > MAX_APPLE_ARTIFACT_BYTES:
                            raise ArtifactError("Apple artifact exceeds its aggregate byte bound")

                        hasher = hashlib.sha256()
                        observed_size = 0
                        destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        destination_descriptor = os.open(
                            destination,
                            destination_flags,
                            0o700 if opened.st_mode & stat.S_IXUSR else 0o600,
                        )
                        try:
                            while True:
                                chunk = os.read(source_file, 1024 * 1024)
                                if not chunk:
                                    break
                                observed_size += len(chunk)
                                if observed_size > opened.st_size:
                                    raise ArtifactError(
                                        f"Apple artifact file grew: {relative_path}"
                                    )
                                hasher.update(chunk)
                                view = memoryview(chunk)
                                while view:
                                    written = os.write(destination_descriptor, view)
                                    if written <= 0:
                                        raise ArtifactError(
                                            f"snapshot write failed: {relative_path}"
                                        )
                                    view = view[written:]
                            os.fsync(destination_descriptor)
                        finally:
                            os.close(destination_descriptor)

                        final = os.fstat(source_file)
                        if (
                            observed_size != opened.st_size
                            or _source_entry_metadata(opened)
                            != _source_entry_metadata(final)
                        ):
                            raise ArtifactError(
                                f"Apple artifact file changed during snapshot: {relative_path}"
                            )
                        inventory.append(
                            {
                                "path": relative_path,
                                "size": observed_size,
                                "sha256": hasher.hexdigest(),
                                "executable": bool(opened.st_mode & stat.S_IXUSR),
                            }
                        )
                    finally:
                        os.close(source_file)

            copy_directory(root_descriptor, "", snapshot_root)
            final_root = os.fstat(root_descriptor)
            if _source_entry_metadata(opened_root) != _source_entry_metadata(final_root):
                raise ArtifactError("Apple artifact root changed during snapshot")
            yield snapshot_root, tuple(sorted(inventory, key=lambda item: item["path"]))
    finally:
        os.close(root_descriptor)


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ArtifactError(f"non-finite JSON value is forbidden: {value}")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            _read_bounded_regular(path, MAX_RELEASE_JSON_BYTES).decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArtifactError(f"read JSON {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ArtifactError(f"expected a JSON object in {path}")
    return payload


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactError(message)


def _require_exact_fields(
    payload: dict[str, Any], expected_fields: frozenset[str], label: str
) -> None:
    observed_fields = set(payload)
    _require(
        observed_fields == expected_fields,
        f"{label} fields differ: missing={sorted(expected_fields - observed_fields)} "
        f"unexpected={sorted(observed_fields - expected_fields)}",
    )


def _require_digest(value: Any, field: str) -> str:
    _require(
        isinstance(value, str)
        and len(value) == 64
        and value != "0" * 64
        and all(character in "0123456789abcdef" for character in value),
        f"{field} must be a nonzero lowercase SHA-256 digest",
    )
    assert isinstance(value, str)
    return value


def _read_identity_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        encoded = _read_bounded_regular(path, 64 * 1024).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArtifactError(f"identity environment is not UTF-8: {path}") from error
    for line in encoded.splitlines():
        if not line:
            continue
        key, separator, value = line.partition("=")
        _require(bool(separator) and bool(key) and bool(value), f"invalid line in {path}")
        _require(key not in values, f"duplicate identity key {key}")
        values[key] = value
    return values


def _digest_base64(hex_digest: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")


def _llvm_nm(root: Path) -> Path:
    rustc_details = _run(["rustc", "-vV"], cwd=root, text=True)
    assert isinstance(rustc_details, str)
    host = next(
        (
            line.removeprefix("host: ")
            for line in rustc_details.splitlines()
            if line.startswith("host: ")
        ),
        None,
    )
    _require(host is not None, "rustc -vV did not report a host triple")
    sysroot = _run(["rustc", "--print", "sysroot"], cwd=root, text=True)
    assert isinstance(sysroot, str)
    tool = Path(sysroot.strip()) / "lib" / "rustlib" / host / "bin" / "llvm-nm"
    _require(tool.is_file() and os.access(tool, os.X_OK), f"missing llvm-nm: {tool}")
    return tool


def _expected_symbols(root: Path) -> set[str]:
    allowlist = root / "include" / "aura_ffi.exports"
    try:
        names = [
            line.strip()
            for line in _read_bounded_regular(allowlist, 1024 * 1024)
            .decode("utf-8")
            .splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except (OSError, UnicodeDecodeError) as error:
        raise ArtifactError(f"read symbol allowlist {allowlist}: {error}") from error
    _require(bool(names), "Aura export allowlist is empty")
    _require(len(names) == len(set(names)), "Aura export allowlist has duplicates")
    _require(
        all(name.startswith("aura_") and name.replace("_", "").isalnum() for name in names),
        "Aura export allowlist contains an invalid symbol",
    )
    return {f"_{name}" for name in names}


def _archive_symbols(root: Path, archive: Path) -> set[str]:
    output = _run(
        [
            str(_llvm_nm(root)),
            "--defined-only",
            "--extern-only",
            str(archive),
        ],
        cwd=root,
        text=True,
    )
    assert isinstance(output, str)
    symbols = set()
    for line in output.splitlines():
        if not line or line.endswith(": no symbols"):
            continue
        symbol = line.split()[-1]
        if symbol.startswith("_aura_"):
            symbols.add(symbol)
    return symbols


def _slice_architectures(root: Path, archive: Path) -> set[str]:
    output = _run(["lipo", "-archs", str(archive)], cwd=root, text=True)
    assert isinstance(output, str)
    return set(output.split())


def _archive_platform_versions(
    root: Path, archive: Path
) -> tuple[tuple[int | None, str], ...]:
    """Return every member's modern platform or legacy iPhoneOS minimum."""

    output = _run(["otool", "-l", str(archive)], cwd=root, text=True)
    assert isinstance(output, str)
    current_member: str | None = None
    current_platform: int | None = None
    current_minos: str | None = None
    current_version_kind: str | None = None
    versions: list[tuple[int | None, str]] = []

    def finish_member() -> None:
        nonlocal current_platform, current_minos, current_version_kind
        if current_member is None:
            return
        _require(
            current_version_kind is not None and current_minos is not None,
            f"archive member lacks one platform version command: {current_member}",
        )
        _require(
            current_version_kind == "legacy" or current_platform is not None,
            f"modern Mach-O platform command lacks platform: {current_member}",
        )
        versions.append((current_platform, current_minos))
        current_platform = None
        current_minos = None
        current_version_kind = None

    archive_prefix = f"{archive}("
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if raw_line.startswith(archive_prefix) and raw_line.endswith("):"):
            finish_member()
            current_member = raw_line[len(str(archive)) + 1 : -2]
            continue
        if line.startswith("cmd LC_VERSION_MIN_"):
            _require(
                line == "cmd LC_VERSION_MIN_IPHONEOS",
                f"wrong legacy Mach-O platform command in {current_member}: {line}",
            )
            _require(
                current_version_kind is None,
                f"archive member has multiple platform commands: {current_member}",
            )
            current_version_kind = "legacy"
            current_platform = None
            continue
        if line == "cmd LC_BUILD_VERSION":
            _require(
                current_version_kind is None,
                f"archive member has multiple platform commands: {current_member}",
            )
            current_version_kind = "modern"
            continue
        if current_version_kind == "modern" and line.startswith("platform "):
            _require(
                current_platform is None,
                f"modern Mach-O command repeats platform: {current_member}",
            )
            try:
                current_platform = int(line.removeprefix("platform "))
            except ValueError as error:
                raise ArtifactError(
                    f"invalid Mach-O platform in {current_member}"
                ) from error
            continue
        if current_version_kind == "modern" and line.startswith("minos "):
            _require(
                current_minos is None,
                f"modern Mach-O command repeats minos: {current_member}",
            )
            current_minos = line.removeprefix("minos ")
            continue
        if (
            current_version_kind == "legacy"
            and current_minos is None
            and line.startswith("version ")
        ):
            current_minos = line.removeprefix("version ")

    finish_member()
    _require(bool(versions), f"archive has no Mach-O members: {archive}")
    return tuple(versions)


def _version_tuple(version: str) -> tuple[int, ...]:
    try:
        components = tuple(int(component) for component in version.split("."))
    except ValueError as error:
        raise ArtifactError(f"invalid Mach-O minimum OS version: {version}") from error
    _require(
        bool(components)
        and len(components) <= 3
        and all(component >= 0 for component in components),
        f"invalid Mach-O minimum OS version: {version}",
    )
    return components


def _verify_architecture_platform(
    root: Path,
    archive: Path,
    *,
    expected_platform: int,
    allow_legacy_iphoneos: bool,
) -> None:
    versions = _archive_platform_versions(root, archive)
    modern_exact_floor = False
    for platform, minimum_os in versions:
        _require(
            _version_tuple(minimum_os) <= _version_tuple("18.0"),
            f"archive member requires an OS newer than 18.0: {minimum_os}",
        )
        if platform is None:
            _require(
                allow_legacy_iphoneos,
                "legacy iPhoneOS platform command is ambiguous for this architecture",
            )
            continue
        _require(
            platform == expected_platform,
            f"archive member has wrong Mach-O platform {platform}, expected {expected_platform}",
        )
        if minimum_os == "18.0":
            modern_exact_floor = True
    _require(
        modern_exact_floor,
        "archive architecture lacks an exact modern platform/minimum-OS 18.0 binding",
    )


def _verify_release_documents(
    root: Path,
    manifest: dict[str, Any],
    descriptor: dict[str, Any],
    *,
    require_clean_source: bool,
) -> tuple[str, bool]:
    _require_exact_fields(manifest, RELEASE_MANIFEST_FIELDS, "release manifest")
    _require_exact_fields(descriptor, RUNTIME_DESCRIPTOR_FIELDS, "runtime descriptor")
    _require(
        manifest.get("schema_version") == RELEASE_MANIFEST_SCHEMA_VERSION,
        f"release manifest schema must be {RELEASE_MANIFEST_SCHEMA_VERSION}",
    )
    _require(
        descriptor.get("schema_version") == RUNTIME_DESCRIPTOR_SCHEMA_VERSION,
        f"runtime descriptor schema must be {RUNTIME_DESCRIPTOR_SCHEMA_VERSION}",
    )

    current_revision = _run(["git", "rev-parse", "HEAD"], cwd=root, text=True)
    assert isinstance(current_revision, str)
    current_revision = current_revision.strip()
    current_digest = source_tree_digest(root)
    current_dirty = source_tree_dirty(root)

    shared_fields = [
        "source_revision",
        "source_tree_dirty",
        "source_tree_sha256",
        "shippable",
        "cargo_profile",
        "cargo_features",
        "runtime_release_version",
        "wire_package",
        "wire_major_version",
        "state_schema_version",
        "ffi_contract_version",
        "aura_ffi_header_sha256",
        "runtime_capabilities_sha256",
        "model_manifest_sha256",
        "execution_policy_trust_keyring_sha256",
    ]
    for field in shared_fields:
        _require(
            manifest.get(field) == descriptor.get(field),
            f"{field} differs between manifest and runtime descriptor",
        )

    source_revision = manifest.get("source_revision")
    _require(
        isinstance(source_revision, str)
        and len(source_revision) == 40
        and all(character in "0123456789abcdef" for character in source_revision),
        "source revision must be a full lowercase Git SHA-1",
    )
    assert isinstance(source_revision, str)
    _require(
        _source_revision_is_ancestor(root, source_revision, current_revision),
        "source revision is not an ancestor of the current revision",
    )
    _require(
        manifest["source_tree_sha256"] == current_digest,
        "source tree digest mismatch",
    )
    _require(
        manifest["source_tree_dirty"] is current_dirty,
        "source-tree dirty flag mismatch",
    )
    _require(
        manifest["shippable"] is (not current_dirty),
        "shippable flag does not match source cleanliness",
    )
    if require_clean_source:
        _require(not current_dirty, "shipping verification requires a clean source tree")
        _require(manifest["shippable"] is True, "shipping manifest is not shippable")

    _require(manifest.get("cargo_profile") == "release", "Cargo profile is not release")
    _require(manifest.get("cargo_locked") is True, "Cargo.lock was not enforced")
    features = manifest.get("cargo_features")
    _require(
        isinstance(features, list)
        and features == sorted(set(features))
        and set(features).issubset({"onnx"}),
        "Cargo features must be a sorted supported set",
    )
    _require(
        manifest.get("wire_package") == "aura.messenger.v1",
        "unexpected protobuf wire package",
    )
    _require(manifest.get("wire_major_version") == 1, "unexpected wire major")
    _require(manifest.get("state_schema_version") == 3, "unexpected state schema")
    _require(manifest.get("ffi_contract_version") == 1, "unexpected FFI contract")
    _require(
        manifest.get("target_triples") == EXPECTED_TARGET_TRIPLES,
        "Apple target triples differ from the release contract",
    )
    _require(manifest.get("minimum_ios_version") == "18.0", "unexpected iOS floor")
    _require(
        manifest.get("model_bundle_included") is False,
        "unexpected model bundle is packaged",
    )

    for field in (
        "source_tree_sha256",
        "aura_ffi_header_sha256",
        "runtime_capabilities_sha256",
        "runtime_artifact_descriptor_sha256",
        "runtime_artifact_identities_env_sha256",
        "model_manifest_sha256",
        "execution_policy_trust_keyring_sha256",
        "xcframework_info_plist_sha256",
    ):
        _require_digest(manifest.get(field), field)
    binary_sha256 = manifest.get("binary_sha256")
    _require(isinstance(binary_sha256, dict), "binary_sha256 must be an object")
    _require(
        set(binary_sha256) == set(EXPECTED_SLICES),
        "binary_sha256 slice set mismatch",
    )
    for slice_id, digest in binary_sha256.items():
        _require_digest(digest, f"binary_sha256.{slice_id}")

    return current_digest, current_dirty


def _verify_artifact_snapshot(
    root: Path,
    dist_dir: Path,
    *,
    require_clean_source: bool = False,
) -> dict[str, Any]:
    """Verify source, manifest, XCFramework slices, headers, and exports."""

    root = root.resolve()
    manifest_path = dist_dir / "release-manifest.json"
    descriptor_path = dist_dir / "runtime-artifact-descriptor.json"
    identities_path = dist_dir / "runtime-artifact-identities.env"
    xcframework = dist_dir / "AuraAgentFFI.xcframework"

    manifest = _load_json(manifest_path)
    descriptor = _load_json(descriptor_path)
    source_digest, source_dirty = _verify_release_documents(
        root,
        manifest,
        descriptor,
        require_clean_source=require_clean_source,
    )

    _require(
        _sha256_file(descriptor_path)
        == manifest["runtime_artifact_descriptor_sha256"],
        "runtime artifact descriptor digest mismatch",
    )
    _require(
        _sha256_file(identities_path)
        == manifest["runtime_artifact_identities_env_sha256"],
        "runtime artifact identities env digest mismatch",
    )

    source_header = root / "include" / "aura_ffi.h"
    source_header_bytes = _read_bounded_regular(source_header, 1024 * 1024)
    _require(
        hashlib.sha256(source_header_bytes).hexdigest()
        == manifest["aura_ffi_header_sha256"],
        "source C header digest mismatch",
    )
    packaged_headers = sorted(xcframework.glob("*/Headers/aura_ffi.h"))
    _require(len(packaged_headers) == 3, "XCFramework must contain exactly 3 headers")
    for header in packaged_headers:
        _require(
            _read_bounded_regular(header, 1024 * 1024) == source_header_bytes,
            f"header drift: {header}",
        )

    trust_keyring = dist_dir / "execution-policy-trust-keyring.json"
    _require(
        _sha256_file(trust_keyring)
        == manifest["execution_policy_trust_keyring_sha256"],
        "execution-policy trust keyring digest mismatch",
    )

    info_path = xcframework / "Info.plist"
    _require(
        _sha256_file(info_path) == manifest["xcframework_info_plist_sha256"],
        "XCFramework Info.plist digest mismatch",
    )
    try:
        info = plistlib.loads(_read_bounded_regular(info_path, 256 * 1024))
    except (OSError, plistlib.InvalidFileException) as error:
        raise ArtifactError(f"read XCFramework Info.plist: {error}") from error
    libraries = info.get("AvailableLibraries")
    _require(isinstance(libraries, list), "Info.plist AvailableLibraries is missing")
    libraries_by_id = {
        library.get("LibraryIdentifier"): library
        for library in libraries
        if isinstance(library, dict)
    }
    _require(
        set(libraries_by_id) == set(EXPECTED_SLICES),
        "Info.plist slice identifiers mismatch",
    )

    expected_symbols = _expected_symbols(root)
    slice_reports = []
    for slice_id, expected in EXPECTED_SLICES.items():
        library = libraries_by_id[slice_id]
        _require(
            library.get("LibraryPath") == expected["library"],
            f"{slice_id} library path mismatch",
        )
        _require(
            library.get("HeadersPath") == "Headers",
            f"{slice_id} headers path mismatch",
        )
        _require(
            set(library.get("SupportedArchitectures", []))
            == expected["architectures"],
            f"{slice_id} plist architecture mismatch",
        )
        _require(
            library.get("SupportedPlatform") == expected["platform"],
            f"{slice_id} platform mismatch",
        )
        _require(
            library.get("SupportedPlatformVariant") == expected["variant"],
            f"{slice_id} platform variant mismatch",
        )

        archive = xcframework / slice_id / expected["library"]
        _require(archive.is_file(), f"missing archive: {archive}")
        digest = _sha256_file(archive)
        _require(
            digest == manifest["binary_sha256"][slice_id],
            f"{slice_id} binary digest mismatch",
        )
        architectures = _slice_architectures(root, archive)
        _require(
            architectures == expected["architectures"],
            f"{slice_id} Mach-O architecture mismatch",
        )
        with tempfile.TemporaryDirectory(prefix="aura-apple-architecture.") as raw:
            architecture_directory = Path(raw)
            for architecture in sorted(architectures):
                architecture_archive = archive
                if len(architectures) > 1:
                    architecture_archive = architecture_directory / f"{architecture}.a"
                    _run(
                        [
                            "lipo",
                            str(archive),
                            "-thin",
                            architecture,
                            "-output",
                            str(architecture_archive),
                        ],
                        cwd=root,
                    )
                _verify_architecture_platform(
                    root,
                    architecture_archive,
                    expected_platform=expected["mach_o_platform"],
                    allow_legacy_iphoneos=(
                        (expected["variant"] is None and architecture == "arm64")
                        or (
                            expected["variant"] == "simulator"
                            and architecture == "x86_64"
                        )
                    ),
                )
                symbols = _archive_symbols(root, architecture_archive)
                _require(
                    symbols == expected_symbols,
                    f"{slice_id}/{architecture} Aura export allowlist mismatch: "
                    f"missing={sorted(expected_symbols - symbols)} "
                    f"unexpected={sorted(symbols - expected_symbols)}",
                )
        slice_reports.append(
            {
                "slice_id": slice_id,
                "architectures": sorted(architectures),
                "binary_sha256": digest,
            }
        )

    identities = _read_identity_env(identities_path)
    expected_identities = {
        "AURA_RUNTIME_CAPABILITIES_SHA256_B64": _digest_base64(
            manifest["runtime_capabilities_sha256"]
        ),
        "AURA_MODEL_MANIFEST_SHA256_B64": _digest_base64(
            manifest["model_manifest_sha256"]
        ),
        "AURA_RELEASE_ARTIFACT_DESCRIPTOR_SHA256_B64": _digest_base64(
            manifest["runtime_artifact_descriptor_sha256"]
        ),
    }
    _require(
        identities == expected_identities,
        "runtime artifact identity environment does not match manifest digests",
    )

    return {
        "schema_version": VERIFICATION_REPORT_SCHEMA,
        "status": "pass",
        "shippable": manifest["shippable"],
        "source_revision": manifest["source_revision"],
        "source_tree_dirty": source_dirty,
        "source_tree_sha256": source_digest,
        "runtime_release_version": manifest["runtime_release_version"],
        "wire_package": manifest["wire_package"],
        "state_schema_version": manifest["state_schema_version"],
        "ffi_contract_version": manifest["ffi_contract_version"],
        "cargo_features": manifest["cargo_features"],
        "slices": slice_reports,
    }


def verify_artifact(
    root: Path,
    dist_dir: Path,
    *,
    require_clean_source: bool = False,
) -> dict[str, Any]:
    """Verify one immutable snapshot of the exact Apple artifact inventory."""

    with snapshot_apple_artifact(dist_dir) as (snapshot, _inventory):
        return _verify_artifact_snapshot(
            root,
            snapshot,
            require_clean_source=require_clean_source,
        )


def _write_report(path: Path | None, report: dict[str, Any]) -> None:
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(encoded, end="")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded, encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Hash source or verify an AURA Apple XCFramework."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    digest = subparsers.add_parser("source-digest")
    digest.add_argument("--root", type=Path, required=True)

    dirty = subparsers.add_parser("source-dirty")
    dirty.add_argument("--root", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--dist-dir", type=Path, required=True)
    verify.add_argument("--output", type=Path)
    verify.add_argument("--require-clean-source", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "source-digest":
            print(source_tree_digest(args.root))
            return 0
        if args.command == "source-dirty":
            print("true" if source_tree_dirty(args.root) else "false")
            return 0

        report = verify_artifact(
            args.root,
            args.dist_dir,
            require_clean_source=args.require_clean_source,
        )
        _write_report(args.output, report)
        if args.output is not None:
            print(f"Apple artifact verification written to {args.output} (status=pass)")
        return 0
    except (ArtifactError, OSError, KeyError, TypeError, ValueError) as error:
        report = {
            "schema_version": VERIFICATION_REPORT_SCHEMA,
            "status": "fail",
            "error": str(error),
        }
        if getattr(args, "command", None) == "verify":
            _write_report(getattr(args, "output", None), report)
        else:
            print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
