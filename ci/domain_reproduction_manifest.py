#!/usr/bin/env python3

"""Materialize a path-free private domain-study reproduction manifest.

The descriptor names controlled local files. This tool opens every file once,
hashes that same immutable descriptor, records its exact size, strips all local
paths, and writes a bounded manifest for Rust cross-link validation. It does
not run the analysis and cannot claim independent reproduction.
"""

import argparse
import json
import os
import stat
import sys
from hashlib import sha256
from pathlib import Path

try:
    from ci import apple_artifact as source_tree_support
    from ci import evidence_attestation as crypto_support
    from ci.domain_result_timestamp_adapter import FrozenAtomicOutput
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import apple_artifact as source_tree_support
    import evidence_attestation as crypto_support
    from domain_result_timestamp_adapter import FrozenAtomicOutput


DESCRIPTOR_SCHEMA_VERSION = "aura.domain.reproduction_materialization_descriptor.v1"
MANIFEST_SCHEMA_VERSION = "aura.domain.independent_reproduction_package.v1"
MAX_DESCRIPTOR_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024 * 1024 * 1024
MAX_PACKAGE_BYTES = 4 * MAX_FILE_BYTES
MAX_FILE_COUNT = 100_000
MAX_PRIMARY_ARTIFACT_COUNT = 40
MAX_TIMESTAMP_MATERIAL_COUNT = 10
MIN_TIMESTAMP_CHAIN_CERTIFICATES = 2
MAX_TIMESTAMP_CHAIN_CERTIFICATES = 7
MAX_TIMESTAMP_REVOCATION_CRLS = 6

PRIMARY_ROLES = (
    "preregistration",
    "policy_evidence",
    "build_provenance",
    "trust_policy",
    "source_tree",
    "cargo_lock",
    "rust_toolchain",
    "evaluated_binary",
    "corpus",
    "known_seed_registry",
    "inclusion_criteria",
    "exclusion_criteria",
    "label_ontology",
    "safe_boundary_definition",
    "split_manifest",
    "attack_construction_manifest",
    "agreement_bootstrap_seed",
    "review_packet",
    "reviewer_assignment",
    "reviewer_decision_bundle",
    "review_coverage_manifest",
    "agreement_analysis_artifact",
    "adjudication_manifest",
    "adjudication_decision_bundle",
    "prediction_bundle",
    "analysis_environment",
    "exclusion_manifest",
    "protocol_deviation_manifest",
    "exploratory_results",
    "result_evidence_bundle",
)
TIMESTAMP_SUBJECT_KINDS = (
    "preregistration_attestation",
    "reviewer_receipt",
    "reviewer_agreement_analysis",
    "adjudication_start_authorization",
    "adjudication_receipt",
    "final_evidence_manifest",
)
TOP_LEVEL_FIELDS = {
    "schema_version",
    "study_id",
    "result_id",
    "preregistration_canonical_sha256",
    "result_bundle_sha256",
    "final_manifest_sha256",
    "evidence_bundle_canonical_sha256",
    "primary_artifacts",
    "timestamp_materials",
    "public_distribution_permitted",
    "independent_recomputation_completed",
}
PRIMARY_FIELDS = {"role", "ordinal", "path"}
TIMESTAMP_FIELDS = {
    "subject_kind",
    "reviewer_index",
    "request_path",
    "response_path",
    "certificate_chain_der_paths",
    "revocation_crl_der_paths",
}

MaterializationError = crypto_support.AttestationError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Hash a controlled private file inventory and write an AURA "
            "domain-study reproduction manifest."
        )
    )
    parser.add_argument("--descriptor", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def reject_duplicate_json_fields(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise MaterializationError(f"duplicate JSON field is not allowed: {key}")
        result[key] = value
    return result


def reject_nonfinite_json_number(value: str) -> None:
    raise MaterializationError(f"non-finite JSON number is not allowed: {value}")


def parse_descriptor(raw: bytes) -> dict:
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_fields,
            parse_constant=reject_nonfinite_json_number,
        )
    except MaterializationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise MaterializationError(
            f"reproduction descriptor is not strict JSON: {error}"
        ) from error
    if not isinstance(payload, dict) or set(payload) != TOP_LEVEL_FIELDS:
        raise MaterializationError("reproduction descriptor fields are not exact")
    if payload["schema_version"] != DESCRIPTOR_SCHEMA_VERSION:
        raise MaterializationError("reproduction descriptor schema is unsupported")
    if not safe_token(payload["study_id"]) or not safe_token(payload["result_id"]):
        raise MaterializationError("study_id or result_id is invalid")
    for field in (
        "preregistration_canonical_sha256",
        "result_bundle_sha256",
        "final_manifest_sha256",
        "evidence_bundle_canonical_sha256",
    ):
        if not canonical_sha256(payload[field]):
            raise MaterializationError(f"{field} is not a canonical SHA-256")
    if (
        payload["public_distribution_permitted"] is not False
        or payload["independent_recomputation_completed"] is not False
    ):
        raise MaterializationError(
            "materialization cannot authorize disclosure or claim a completed rerun"
        )
    validate_primary_descriptors(payload["primary_artifacts"])
    validate_timestamp_descriptors(payload["timestamp_materials"])
    return payload


def validate_primary_descriptors(entries: object) -> None:
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_PRIMARY_ARTIFACT_COUNT:
        raise MaterializationError("primary artifact count is outside the supported bound")
    keys = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != PRIMARY_FIELDS:
            raise MaterializationError("primary artifact descriptor fields are not exact")
        role = entry["role"]
        ordinal = entry["ordinal"]
        if role not in PRIMARY_ROLES or not unsigned_u16(ordinal) or not safe_path(entry["path"]):
            raise MaterializationError("primary artifact role, ordinal, or path is invalid")
        if role not in ("reviewer_assignment", "reviewer_decision_bundle") and ordinal != 0:
            raise MaterializationError("singleton primary artifact ordinal must be zero")
        key = role, ordinal
        if key in keys:
            raise MaterializationError("primary artifact role and ordinal are duplicated")
        keys.add(key)


def validate_timestamp_descriptors(entries: object) -> None:
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_TIMESTAMP_MATERIAL_COUNT:
        raise MaterializationError("timestamp material count is outside the supported bound")
    keys = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != TIMESTAMP_FIELDS:
            raise MaterializationError("timestamp material descriptor fields are not exact")
        subject_kind = entry["subject_kind"]
        reviewer_index = entry["reviewer_index"]
        if subject_kind not in TIMESTAMP_SUBJECT_KINDS:
            raise MaterializationError("timestamp subject_kind is unsupported")
        if subject_kind == "reviewer_receipt":
            if not unsigned_u16(reviewer_index):
                raise MaterializationError("reviewer timestamp requires a u16 reviewer_index")
        elif reviewer_index is not None:
            raise MaterializationError("non-reviewer timestamp cannot have a reviewer_index")
        if not safe_path(entry["request_path"]) or not safe_path(entry["response_path"]):
            raise MaterializationError("timestamp request or response path is invalid")
        validate_path_list(
            entry["certificate_chain_der_paths"],
            MIN_TIMESTAMP_CHAIN_CERTIFICATES,
            MAX_TIMESTAMP_CHAIN_CERTIFICATES,
            "certificate chain",
        )
        validate_path_list(
            entry["revocation_crl_der_paths"],
            1,
            MAX_TIMESTAMP_REVOCATION_CRLS,
            "revocation CRL",
        )
        if len(entry["revocation_crl_der_paths"]) + 1 != len(
            entry["certificate_chain_der_paths"]
        ):
            raise MaterializationError(
                "timestamp CRL count must cover every non-anchor certificate"
            )
        key = subject_kind, reviewer_index
        if key in keys:
            raise MaterializationError("timestamp subject and reviewer_index are duplicated")
        keys.add(key)


def validate_path_list(value: object, minimum: int, maximum: int, label: str) -> None:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
        or any(not safe_path(path) for path in value)
    ):
        raise MaterializationError(f"timestamp {label} paths are invalid")


def safe_token(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128 and value.isascii() and all(
        character.isalnum() or character in "_.-" for character in value
    )


def canonical_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def unsigned_u16(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65_535


def safe_path(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 4_096 and "\x00" not in value


def descriptor_paths(descriptor_path: Path, descriptor: dict) -> list[Path]:
    base = descriptor_path.parent

    def local(value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else base / path

    paths = [descriptor_path]
    paths.extend(
        local(entry["path"])
        for entry in descriptor["primary_artifacts"]
        if entry["role"] != "source_tree"
    )
    for entry in descriptor["timestamp_materials"]:
        paths.extend((local(entry["request_path"]), local(entry["response_path"])))
        paths.extend(local(path) for path in entry["certificate_chain_der_paths"])
        paths.extend(local(path) for path in entry["revocation_crl_der_paths"])
    return paths


def hash_file(path: Path, label: str) -> tuple[dict, tuple[int, int]]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise MaterializationError(
            f"{label} is missing, symbolic, or cannot be opened safely: {path}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise MaterializationError(f"{label} is not a regular file: {path}")
        if before.st_size <= 0 or before.st_size > MAX_FILE_BYTES:
            raise MaterializationError(
                f"{label} size must be within 1..={MAX_FILE_BYTES} bytes"
            )
        digest = sha256()
        byte_length = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            byte_length += len(chunk)
            if byte_length > MAX_FILE_BYTES:
                raise MaterializationError(f"{label} exceeds the supported byte bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if byte_length != before.st_size or before_identity != after_identity:
            raise MaterializationError(f"{label} changed while it was being hashed")
        return (
            {"sha256": digest.hexdigest(), "byte_length": byte_length},
            (before.st_dev, before.st_ino),
        )
    finally:
        os.close(descriptor)


def materialize(descriptor_path: Path, output_path: Path) -> dict:
    raw, descriptor_identity = crypto_support.read_bounded_with_identity(
        descriptor_path,
        MAX_DESCRIPTOR_BYTES,
        "reproduction descriptor",
    )
    descriptor = parse_descriptor(raw)
    protected = descriptor_paths(descriptor_path, descriptor)
    base = descriptor_path.parent

    def local(value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else base / path

    source_roots = [
        local(entry["path"]).resolve()
        for entry in descriptor["primary_artifacts"]
        if entry["role"] == "source_tree"
    ]
    resolved_descriptor = descriptor_path.resolve()
    resolved_output = output_path.resolve()
    for source_root in source_roots:
        if not source_root.is_dir():
            raise MaterializationError(f"source_tree is not a directory: {source_root}")
        if source_tree_support.source_tree_dirty(source_root):
            raise MaterializationError("source_tree must be clean for confirmatory materialization")
        if resolved_descriptor.is_relative_to(source_root):
            raise MaterializationError("reproduction descriptor must be outside source_tree")
        if resolved_output.is_relative_to(source_root):
            raise MaterializationError("reproduction output must be outside source_tree")

    with FrozenAtomicOutput(output_path, protected) as frozen_output:
        frozen_output.protect_identities({descriptor_identity})
        observed_identities = set()
        source_snapshots = []
        primary_artifacts = []
        for entry in descriptor["primary_artifacts"]:
            artifact_path = local(entry["path"])
            if entry["role"] == "source_tree":
                try:
                    digest, covered_file_count, byte_length, source_identities = (
                        source_tree_support.source_tree_identity(artifact_path)
                    )
                except source_tree_support.ArtifactError as error:
                    raise MaterializationError(str(error)) from error
                if artifact_path.resolve() != source_roots.pop(0):
                    raise MaterializationError("source_tree path changed during materialization")
                if byte_length > MAX_FILE_BYTES:
                    raise MaterializationError("source_tree exceeds the supported byte bound")
                observed_identities.update(source_identities)
                source_snapshots.append(
                    (
                        artifact_path.resolve(),
                        digest,
                        covered_file_count,
                        byte_length,
                        source_identities,
                    )
                )
                identity = {"sha256": digest, "byte_length": byte_length}
                digest_kind = "build_source_tree_v2"
            else:
                identity, file_identity = hash_file(
                    artifact_path,
                    f"{entry['role']}[{entry['ordinal']}]",
                )
                observed_identities.add(file_identity)
                covered_file_count = 1
                digest_kind = (
                    "canonical_json_sha256"
                    if entry["role"]
                    in {
                        "preregistration",
                        "policy_evidence",
                        "build_provenance",
                        "trust_policy",
                        "known_seed_registry",
                        "reviewer_assignment",
                        "review_coverage_manifest",
                        "adjudication_manifest",
                        "result_evidence_bundle",
                    }
                    else "raw_file_sha256"
                )
            primary_artifacts.append(
                {
                    "role": entry["role"],
                    "ordinal": entry["ordinal"],
                    "digest_kind": digest_kind,
                    "covered_file_count": covered_file_count,
                    **identity,
                }
            )
        primary_artifacts.sort(
            key=lambda entry: (PRIMARY_ROLES.index(entry["role"]), entry["ordinal"])
        )

        timestamp_materials = []
        for entry in descriptor["timestamp_materials"]:
            request, request_identity = hash_file(
                local(entry["request_path"]), "timestamp request"
            )
            response, response_identity = hash_file(
                local(entry["response_path"]), "timestamp response"
            )
            observed_identities.update((request_identity, response_identity))
            chain = []
            for path in entry["certificate_chain_der_paths"]:
                identity, file_identity = hash_file(local(path), "timestamp certificate DER")
                observed_identities.add(file_identity)
                chain.append(identity)
            if len({item["sha256"] for item in chain}) != len(chain):
                raise MaterializationError("timestamp certificate chain contains duplicate DER")
            crls = []
            for path in entry["revocation_crl_der_paths"]:
                identity, file_identity = hash_file(local(path), "timestamp CRL DER")
                observed_identities.add(file_identity)
                crls.append(identity)
            crls.sort(key=lambda item: item["sha256"])
            if len({item["sha256"] for item in crls}) != len(crls):
                raise MaterializationError("timestamp CRL set contains duplicate DER")
            timestamp_materials.append(
                {
                    "subject_kind": entry["subject_kind"],
                    "reviewer_index": entry["reviewer_index"],
                    "request": request,
                    "response": response,
                    "certificate_chain_der": chain,
                    "revocation_crl_der": crls,
                }
            )
        timestamp_materials.sort(
            key=lambda entry: (
                TIMESTAMP_SUBJECT_KINDS.index(entry["subject_kind"]),
                -1 if entry["reviewer_index"] is None else entry["reviewer_index"],
            )
        )
        for source_root, digest, covered_count, byte_length, identities in source_snapshots:
            if source_tree_support.source_tree_dirty(source_root):
                raise MaterializationError(
                    "source_tree changed or became dirty during materialization"
                )
            try:
                repeated = source_tree_support.source_tree_identity(source_root)
            except source_tree_support.ArtifactError as error:
                raise MaterializationError(str(error)) from error
            if repeated != (digest, covered_count, byte_length, identities):
                raise MaterializationError("source_tree changed during materialization")
        frozen_output.protect_identities(observed_identities)

        files = [entry for entry in primary_artifacts]
        file_count = sum(entry["covered_file_count"] for entry in files)
        total_file_bytes = sum(entry["byte_length"] for entry in files)
        for entry in timestamp_materials:
            timestamp_files = [
                entry["request"],
                entry["response"],
                *entry["certificate_chain_der"],
                *entry["revocation_crl_der"],
            ]
            file_count += len(timestamp_files)
            total_file_bytes += sum(item["byte_length"] for item in timestamp_files)
        if file_count > MAX_FILE_COUNT or total_file_bytes > MAX_PACKAGE_BYTES:
            raise MaterializationError("reproduction package exceeds its aggregate bound")

        manifest = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "study_id": descriptor["study_id"],
            "result_id": descriptor["result_id"],
            "preregistration_canonical_sha256": descriptor[
                "preregistration_canonical_sha256"
            ],
            "result_bundle_sha256": descriptor["result_bundle_sha256"],
            "final_manifest_sha256": descriptor["final_manifest_sha256"],
            "evidence_bundle_canonical_sha256": descriptor[
                "evidence_bundle_canonical_sha256"
            ],
            "primary_artifacts": primary_artifacts,
            "timestamp_materials": timestamp_materials,
            "file_count": file_count,
            "total_file_bytes": total_file_bytes,
            "public_distribution_permitted": False,
            "independent_recomputation_completed": False,
        }
        frozen_output.write_bytes(
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )
    return manifest


def main() -> int:
    args = parse_args()
    try:
        manifest = materialize(Path(args.descriptor), Path(args.output))
        print(
            "private reproduction manifest written: "
            f"{manifest['file_count']} files, {manifest['total_file_bytes']} bytes"
        )
        return 0
    except (MaterializationError, UnicodeDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
