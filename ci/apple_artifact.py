#!/usr/bin/env python3
"""Build-source identity and verification helpers for Apple release artifacts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import plistlib
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


RELEASE_MANIFEST_SCHEMA_VERSION = 5
RUNTIME_DESCRIPTOR_SCHEMA_VERSION = 3
VERIFICATION_REPORT_SCHEMA = "aura.apple_artifact_verification.v1"
SOURCE_TREE_DIGEST_DOMAIN = b"aura.source-tree.v1\0"

GENERATED_SOURCE_PATHS = {
    "dist/apple/release-manifest.json",
    "dist/apple/runtime-artifact-descriptor.json",
    "dist/apple/runtime-artifact-identities.env",
}
GENERATED_SOURCE_PREFIXES = ("dist/apple/AuraAgentFFI.xcframework/",)

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
    },
    "ios-arm64_x86_64-simulator": {
        "library": "libaura_agent_ffi_ios_sim.a",
        "architectures": {"arm64", "x86_64"},
        "platform": "ios",
        "variant": "simulator",
    },
    "ios-arm64_x86_64-maccatalyst": {
        "library": "libaura_agent_ffi_maccatalyst.a",
        "architectures": {"arm64", "x86_64"},
        "platform": "ios",
        "variant": "maccatalyst",
    },
}


class ArtifactError(RuntimeError):
    """Raised when release provenance or packaged content is inconsistent."""


def _run(
    args: list[str],
    *,
    cwd: Path,
    text: bool = False,
) -> str | bytes:
    result = subprocess.run(
        args,
        cwd=cwd,
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


def _is_generated_source_path(relative_path: str) -> bool:
    return relative_path in GENERATED_SOURCE_PATHS or relative_path.startswith(
        GENERATED_SOURCE_PREFIXES
    )


def _source_paths(root: Path) -> list[str]:
    paths = _git_paths(
        root,
        ["ls-files", "--cached", "--others", "--exclude-standard"],
    )
    return sorted(path for path in paths if not _is_generated_source_path(path))


def _frame(hasher: Any, payload: bytes) -> None:
    hasher.update(len(payload).to_bytes(8, byteorder="big"))
    hasher.update(payload)


def source_tree_digest(root: Path) -> str:
    """Hash the reviewable source tree while excluding generated Apple outputs."""

    root = root.resolve()
    paths = _source_paths(root)
    if not paths:
        raise ArtifactError(f"no Git source paths found under {root}")

    hasher = hashlib.sha256()
    hasher.update(SOURCE_TREE_DIGEST_DOMAIN)
    for relative_path in paths:
        path = root / relative_path
        _frame(hasher, relative_path.encode("utf-8", errors="surrogateescape"))

        if path.is_symlink():
            hasher.update(b"L")
            _frame(
                hasher,
                os.readlink(path).encode("utf-8", errors="surrogateescape"),
            )
        elif path.is_file():
            hasher.update(b"F")
            executable = bool(path.stat().st_mode & stat.S_IXUSR)
            hasher.update(b"X" if executable else b"-")
            _frame(hasher, path.read_bytes())
        elif not path.exists():
            hasher.update(b"D")
        else:
            raise ArtifactError(f"unsupported source-tree entry: {relative_path}")

    return hasher.hexdigest()


def source_tree_dirty(root: Path) -> bool:
    """Return whether reviewable source differs from HEAD/index."""

    root = root.resolve()
    changed = set()
    changed.update(_git_paths(root, ["diff", "--name-only"]))
    changed.update(_git_paths(root, ["diff", "--cached", "--name-only"]))
    changed.update(
        _git_paths(root, ["ls-files", "--others", "--exclude-standard"])
    )
    return any(not _is_generated_source_path(path) for path in changed)


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


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ArtifactError(f"read JSON {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ArtifactError(f"expected a JSON object in {path}")
    return payload


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactError(message)


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
    for line in path.read_text(encoding="utf-8").splitlines():
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
            for line in allowlist.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError as error:
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


def _verify_release_documents(
    root: Path,
    manifest: dict[str, Any],
    descriptor: dict[str, Any],
    *,
    require_clean_source: bool,
) -> tuple[str, bool]:
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


def verify_artifact(
    root: Path,
    dist_dir: Path,
    *,
    require_clean_source: bool = False,
) -> dict[str, Any]:
    """Verify source, manifest, XCFramework slices, headers, and exports."""

    root = root.resolve()
    dist_dir = dist_dir.resolve()
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
    _require(
        _sha256_file(source_header) == manifest["aura_ffi_header_sha256"],
        "source C header digest mismatch",
    )
    packaged_headers = sorted(xcframework.glob("*/Headers/aura_ffi.h"))
    _require(len(packaged_headers) == 3, "XCFramework must contain exactly 3 headers")
    for header in packaged_headers:
        _require(header.read_bytes() == source_header.read_bytes(), f"header drift: {header}")
    _require(
        not list(xcframework.rglob("module.modulemap")),
        "XCFramework must not contain nested module maps",
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
        info = plistlib.loads(info_path.read_bytes())
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
        symbols = _archive_symbols(root, archive)
        _require(
            symbols == expected_symbols,
            f"{slice_id} Aura export allowlist mismatch: "
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
