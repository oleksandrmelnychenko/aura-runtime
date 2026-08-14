#!/usr/bin/env python3

"""Fail-closed extraction of exact hosted release-evidence artifacts."""

import argparse
import ctypes
import errno
import os
import secrets
import stat
import sys
import zipfile
from hashlib import sha256
from pathlib import Path, PurePosixPath


MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_ENTRY_COUNT = 256

PROMOTION_FILES = frozenset(
    {
        "audit-evidence.json",
        "community-surface-report.json",
        "contract-evidence.json",
        "dataset-evidence.json",
        "evidence-manifest.json",
        "ffi-header-smoke.json",
        "ffi-state-sync-soak.json",
        "kids-memory-health.json",
        "kids-preprod-dry-run-matrix.json",
        "performance/world-performance-summary.json",
        "pilot-gate-report.json",
        "pilot-regression-report.json",
        "pilot-shadow-bundle.json",
        "refactor-candidate.json",
        "refactor-diff-report.json",
        "release-report.json",
        "temporal-shadow-report.json",
        "temporal-shadow-telemetry-validation.json",
        "world-lifecycle-suite-report.json",
    }
)

APPLE_FILES = frozenset(
    {
        "apple-release-verification.json",
        "apple-reproducibility.json",
        "apple-verified-dist/AuraAgentFFI.xcframework/Info.plist",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64/Headers/aura_ffi.h",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64/libaura_agent_ffi.a",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/Headers/aura_ffi.h",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/libaura_agent_ffi_maccatalyst.a",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/Headers/aura_ffi.h",
        "apple-verified-dist/AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/libaura_agent_ffi_ios_sim.a",
        "apple-verified-dist/execution-policy-trust-keyring.json",
        "apple-verified-dist/release-manifest.json",
        "apple-verified-dist/runtime-artifact-descriptor.json",
        "apple-verified-dist/runtime-artifact-identities.env",
    }
)

PROFILES = {"promotion": PROMOTION_FILES, "apple": APPLE_FILES}


class ArtifactIngestError(Exception):
    """The downloaded artifact is malformed, unsafe, or not the pinned object."""


def _open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY
    for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def _stable_archive(
    path: Path, expected_sha256: str, expected_bytes: int
) -> tuple[int, os.stat_result]:
    if (
        len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
        or isinstance(expected_bytes, bool)
        or not 1 <= expected_bytes <= MAX_ARCHIVE_BYTES
    ):
        raise ArtifactIngestError("artifact identity is malformed or exceeds its limit")
    try:
        descriptor = os.open(path, _open_flags())
    except OSError as error:
        raise ArtifactIngestError("artifact archive is inaccessible or unsafe") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != expected_bytes
        ):
            raise ArtifactIngestError("artifact archive type or byte length is invalid")
        digest = sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > MAX_ARCHIVE_BYTES:
                raise ArtifactIngestError("artifact archive exceeds its size limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if observed != expected_bytes or identity_before != identity_after:
            raise ArtifactIngestError("artifact archive changed while it was hashed")
        if digest.hexdigest() != expected_sha256:
            raise ArtifactIngestError("artifact archive SHA-256 does not match its pin")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, after
    except Exception:
        os.close(descriptor)
        raise


def _safe_member_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value:
        raise ArtifactIngestError("artifact contains an unsafe ZIP path")
    candidate = PurePosixPath(value.rstrip("/"))
    if (
        candidate.is_absolute()
        or candidate.as_posix() != value.rstrip("/")
        or any(part in ("", ".", "..") for part in candidate.parts)
    ):
        raise ArtifactIngestError("artifact contains an unsafe ZIP path")
    return candidate


def _validate_members(
    archive: zipfile.ZipFile, expected_files: frozenset[str]
) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ENTRY_COUNT:
        raise ArtifactIngestError("artifact ZIP entry count is invalid")
    expected_directories = {
        PurePosixPath(*PurePosixPath(path).parts[:index]).as_posix()
        for path in expected_files
        for index in range(1, len(PurePosixPath(path).parts))
    }
    files: list[zipfile.ZipInfo] = []
    observed_paths: set[str] = set()
    total = 0
    for info in infos:
        candidate = _safe_member_path(info.filename)
        relative = candidate.as_posix()
        if relative in observed_paths:
            raise ArtifactIngestError("artifact ZIP contains a duplicate path")
        observed_paths.add(relative)
        if info.flag_bits & 0x1:
            raise ArtifactIngestError("encrypted ZIP entries are forbidden")
        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)
        if info.is_dir():
            if relative not in expected_directories or kind not in (0, stat.S_IFDIR):
                raise ArtifactIngestError("artifact ZIP contains an unexpected directory")
            continue
        if relative not in expected_files or kind not in (0, stat.S_IFREG):
            raise ArtifactIngestError("artifact ZIP contains an unexpected or special file")
        if not 1 <= info.file_size <= MAX_FILE_BYTES:
            raise ArtifactIngestError("artifact ZIP member size is invalid")
        total += info.file_size
        if total > MAX_EXTRACTED_BYTES:
            raise ArtifactIngestError("artifact extracted-byte total exceeds its limit")
        files.append(info)
    if {PurePosixPath(info.filename).as_posix() for info in files} != expected_files:
        raise ArtifactIngestError("artifact ZIP inventory is missing required files")
    return files


def _open_or_create_directory(parent_descriptor: int, name: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
    except FileExistsError:
        pass
    try:
        descriptor = os.open(
            name, _open_flags(directory=True), dir_fd=parent_descriptor
        )
    except OSError as error:
        raise ArtifactIngestError("artifact output directory is unsafe") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ArtifactIngestError("artifact output component is not a directory")
    return descriptor


def _write_member(
    root_descriptor: int, archive: zipfile.ZipFile, info: zipfile.ZipInfo
) -> tuple[int, str]:
    parts = PurePosixPath(info.filename).parts
    current = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            child = _open_or_create_directory(current, part)
            os.close(current)
            current = child
        try:
            output = os.open(
                parts[-1],
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=current,
            )
        except OSError as error:
            raise ArtifactIngestError("artifact output file cannot be created safely") from error
        observed = 0
        digest = sha256()
        try:
            with archive.open(info, "r") as source:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    observed += len(chunk)
                    if observed > info.file_size:
                        raise ArtifactIngestError("artifact member expanded past its claim")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(output, view)
                        if written <= 0:
                            raise ArtifactIngestError("artifact member write did not progress")
                        view = view[written:]
            if observed != info.file_size:
                raise ArtifactIngestError("artifact member length does not match its claim")
            os.fsync(output)
        finally:
            os.close(output)
        os.fsync(current)
        return observed, digest.hexdigest()
    finally:
        os.close(current)


def _snapshot_extracted_tree(
    directory_descriptor: int, prefix: tuple[str, ...] = ()
) -> dict[str, tuple[int, str]]:
    snapshot: dict[str, tuple[int, str]] = {}
    directory_before = os.fstat(directory_descriptor)
    entries = list(os.scandir(directory_descriptor))
    for entry in entries:
        if entry.name in ("", ".", ".."):
            raise ArtifactIngestError("artifact output contains an unsafe path")
        metadata = entry.stat(follow_symlinks=False)
        relative_parts = (*prefix, entry.name)
        relative = PurePosixPath(*relative_parts).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ArtifactIngestError(
                    "artifact output directory permissions are invalid"
                )
            try:
                child = os.open(
                    entry.name,
                    _open_flags(directory=True),
                    dir_fd=directory_descriptor,
                )
            except OSError as error:
                raise ArtifactIngestError(
                    "artifact output directory changed during verification"
                ) from error
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    raise ArtifactIngestError(
                        "artifact output directory identity is unstable"
                    )
                snapshot.update(_snapshot_extracted_tree(child, relative_parts))
                after = os.fstat(child)
                observed_after = os.stat(
                    entry.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if (
                    after.st_dev,
                    after.st_ino,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ) != (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_mtime_ns,
                    opened.st_ctime_ns,
                ) or (observed_after.st_dev, observed_after.st_ino) != (
                    opened.st_dev,
                    opened.st_ino,
                ):
                    raise ArtifactIngestError(
                        "artifact output directory changed during verification"
                    )
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ArtifactIngestError(
                "artifact output contains a non-regular or hardlinked file"
            )
        try:
            descriptor = os.open(
                entry.name,
                _open_flags(),
                dir_fd=directory_descriptor,
            )
        except OSError as error:
            raise ArtifactIngestError(
                "artifact output file changed during verification"
            ) from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or (before.st_dev, before.st_ino)
                != (metadata.st_dev, metadata.st_ino)
                or not 1 <= before.st_size <= MAX_FILE_BYTES
            ):
                raise ArtifactIngestError(
                    "artifact output file identity or size is invalid"
                )
            digest = sha256()
            observed = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > MAX_FILE_BYTES:
                    raise ArtifactIngestError(
                        "artifact output file exceeds its size limit"
                    )
                digest.update(chunk)
            after = os.fstat(descriptor)
            observed_after = os.stat(
                entry.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                after.st_dev,
                after.st_ino,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) != (
                before.st_dev,
                before.st_ino,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) or observed != before.st_size or (
                observed_after.st_dev,
                observed_after.st_ino,
                observed_after.st_mode,
                observed_after.st_nlink,
                observed_after.st_size,
                observed_after.st_mtime_ns,
                observed_after.st_ctime_ns,
            ) != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ):
                raise ArtifactIngestError(
                    "artifact output file changed during verification"
                )
            snapshot[relative] = (observed, digest.hexdigest())
        finally:
            os.close(descriptor)
    names_after = sorted(entry.name for entry in os.scandir(directory_descriptor))
    directory_after = os.fstat(directory_descriptor)
    if names_after != sorted(entry.name for entry in entries) or (
        directory_after.st_dev,
        directory_after.st_ino,
        directory_after.st_mtime_ns,
        directory_after.st_ctime_ns,
    ) != (
        directory_before.st_dev,
        directory_before.st_ino,
        directory_before.st_mtime_ns,
        directory_before.st_ctime_ns,
    ):
        raise ArtifactIngestError(
            "artifact output directory changed during verification"
        )
    return snapshot


def _rename_noreplace_at(
    parent_descriptor: int, source_name: str, target_name: str
) -> None:
    source_bytes = os.fsencode(source_name)
    target_bytes = os.fsencode(target_name)
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(library, "renameatx_np"):
        function = library.renameatx_np
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(
            parent_descriptor,
            source_bytes,
            parent_descriptor,
            target_bytes,
            0x00000004,  # RENAME_EXCL
        )
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        function = library.renameat2
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(
            parent_descriptor,
            source_bytes,
            parent_descriptor,
            target_bytes,
            1,  # RENAME_NOREPLACE
        )
    else:
        raise ArtifactIngestError(
            "platform lacks an atomic no-replace publish primitive"
        )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in (errno.EEXIST, errno.ENOTEMPTY):
            raise ArtifactIngestError("artifact output appeared during publication")
        raise ArtifactIngestError("artifact output could not be published atomically")


def extract_artifact(
    archive_path: Path,
    expected_sha256: str,
    expected_bytes: int,
    profile: str,
    output: Path,
) -> None:
    expected_files = PROFILES.get(profile)
    if expected_files is None:
        raise ArtifactIngestError("artifact profile is unsupported")
    if output.name in ("", ".", ".."):
        raise ArtifactIngestError("artifact output path is invalid")
    parent = Path(os.path.abspath(output.parent))
    try:
        parent_metadata = os.lstat(parent)
    except OSError as error:
        raise ArtifactIngestError("artifact output parent is inaccessible") from error
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise ArtifactIngestError("artifact output parent must be a real directory")
    try:
        parent_descriptor = os.open(parent, _open_flags(directory=True))
    except OSError as error:
        raise ArtifactIngestError("artifact output parent cannot be safely opened") from error
    archive_descriptor: int | None = None
    root_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        opened_parent = os.fstat(parent_descriptor)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_metadata.st_dev,
            parent_metadata.st_ino,
        ):
            raise ArtifactIngestError("artifact output parent changed while opening")
        try:
            os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ArtifactIngestError("artifact output must be fresh")
        for _attempt in range(128):
            candidate = f".{output.name}.{secrets.token_hex(12)}"
            try:
                os.mkdir(candidate, mode=0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if temporary_name is None:
            raise ArtifactIngestError(
                "cannot allocate a fresh artifact staging directory"
            )
        root_descriptor = os.open(
            temporary_name, _open_flags(directory=True), dir_fd=parent_descriptor
        )
        archive_descriptor, archive_metadata = _stable_archive(
            archive_path, expected_sha256, expected_bytes
        )
        expected_snapshot: dict[str, tuple[int, str]] = {}
        with os.fdopen(os.dup(archive_descriptor), "rb") as archive_handle:
            with zipfile.ZipFile(archive_handle, "r") as archive:
                members = _validate_members(archive, expected_files)
                for info in sorted(members, key=lambda member: member.filename):
                    expected_snapshot[info.filename] = _write_member(
                        root_descriptor, archive, info
                    )
        after = os.fstat(archive_descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            archive_metadata.st_dev,
            archive_metadata.st_ino,
            archive_metadata.st_nlink,
            archive_metadata.st_size,
            archive_metadata.st_mtime_ns,
            archive_metadata.st_ctime_ns,
        ):
            raise ArtifactIngestError("artifact archive changed during extraction")
        os.fsync(root_descriptor)
        if _snapshot_extracted_tree(root_descriptor) != expected_snapshot:
            raise ArtifactIngestError(
                "artifact output does not match the verified archive bytes"
            )
        observed_parent = os.lstat(parent)
        if (
            stat.S_ISLNK(observed_parent.st_mode)
            or not stat.S_ISDIR(observed_parent.st_mode)
            or (observed_parent.st_dev, observed_parent.st_ino)
            != (opened_parent.st_dev, opened_parent.st_ino)
        ):
            raise ArtifactIngestError("artifact output parent changed during extraction")
        _rename_noreplace_at(parent_descriptor, temporary_name, output.name)
        temporary_name = None
        published = os.stat(
            output.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        opened_root = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(published.st_mode)
            or (published.st_dev, published.st_ino)
            != (opened_root.st_dev, opened_root.st_ino)
        ):
            raise ArtifactIngestError(
                "artifact output was replaced during publication"
            )
        if _snapshot_extracted_tree(root_descriptor) != expected_snapshot:
            raise ArtifactIngestError(
                "published artifact output changed during final verification"
            )
        os.fsync(parent_descriptor)
        published_after = os.stat(
            output.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(published_after.st_mode)
            or (published_after.st_dev, published_after.st_ino)
            != (opened_root.st_dev, opened_root.st_ino)
        ):
            raise ArtifactIngestError(
                "artifact output was replaced after final verification"
            )
    except ArtifactIngestError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as error:
        raise ArtifactIngestError("artifact ZIP extraction failed") from error
    finally:
        if archive_descriptor is not None:
            os.close(archive_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
        # Never remove a path by name after an error. A concurrent writer can
        # swap that name between validation and unlink/rmdir; retaining a
        # private, randomly named partial staging directory is fail-safe.
        os.close(parent_descriptor)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify and safely extract an exact hosted release artifact."
    )
    parser.add_argument("--archive", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-bytes", required=True, type=int)
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        extract_artifact(
            Path(args.archive),
            args.expected_sha256,
            args.expected_bytes,
            args.profile,
            Path(args.output),
        )
    except ArtifactIngestError as error:
        print(f"release artifact ingest error: {error}", file=sys.stderr)
        return 2
    print(f"verified {args.profile} release artifact extracted to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
