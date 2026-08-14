#!/usr/bin/env python3

"""Assemble and verify a terminal, unsigned AURA release dossier.

The dossier is deliberately an index, not another authorization authority.  A
release decision and its detached operator attestation remain governed by
``ci.release_decision``.  Public keys are external trust roots and are never
copied into a dossier.
"""

import argparse
import ctypes
import errno
import hmac
import json
import math
import os
import secrets
import stat
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath

try:
    from ci import pilot_signoff_verification, release_decision
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import pilot_signoff_verification
    import release_decision


SCHEMA_VERSION = "aura.release_candidate_dossier.v2"
VERIFICATION_SCHEMA_VERSION = "aura.release_candidate_dossier_verification.v2"
PILOT_SIGNOFF_VERIFICATION_SCHEMA_VERSION = (
    pilot_signoff_verification.VERIFICATION_SCHEMA_VERSION
)
PILOT_SIGNOFF_TRUST_POLICY_SCHEMA_VERSION = (
    pilot_signoff_verification.TRUST_POLICY_SCHEMA_VERSION
)
PILOT_SIGNOFF_SIGNATURE_ALGORITHM = pilot_signoff_verification.SIGNATURE_ALGORITHM
INDEX_PATH = "dossier.json"
DECISION_PATH = "decision/release-decision.json"
RELEASE_ATTESTATION_PATH = "decision/release-decision.attestation.json"
RELEASE_VERIFICATION_PATH = (
    "decision/release-decision.attestation-verification.json"
)
MAX_INDEX_BYTES = 1024 * 1024
MAX_KEY_BYTES = release_decision.MAX_ATTESTATION_BYTES
MAX_ARTIFACT_BYTES = release_decision.MAX_ARTIFACT_BYTES
MAX_PILOT_SIGNOFF_TRUST_POLICY_BYTES = 64 * 1024

PILOT_REQUIRED_REVIEW_AREAS = pilot_signoff_verification.REQUIRED_REVIEW_AREAS
PILOT_SIGNOFF_VERIFICATION_FIELDS = {
    "schema_version",
    "status",
    "release_revision",
    "trust_policy_sha256",
    "policy_id",
    "policy_epoch",
    "signature_algorithm",
    "required_review_areas",
    "verified_signoff_count",
    "distinct_signer_count",
    "signoff_set_sha256",
    "signer_spki_sha256",
    "signer_spki_set_sha256",
    "attestations",
}
PILOT_TRUST_POLICY_FIELDS = {
    "schema_version",
    "policy_id",
    "policy_epoch",
    "roles",
}
PILOT_TRUST_ROLE_FIELDS = {
    "area",
    "reviewer",
    "key_id",
    "public_key_hex",
}

SOURCE_PATHS = {
    "evidence_manifest": "evidence/evidence-manifest.json",
    "evidence_attestation": "evidence/evidence-manifest.attestation.json",
    "evidence_attestation_verification": (
        "evidence/evidence-manifest.attestation-verification.json"
    ),
    "apple_artifact_verification": "apple/apple-release-verification.json",
    "apple_artifact_reproducibility": "apple/apple-reproducibility.json",
    "apple_release_manifest": "apple/release-manifest.json",
    "pilot_gate_report": "pilot/pilot-gate-report.json",
    "pilot_signoff_verification": "pilot/pilot-signoff-verification.json",
    "product_integration_acceptance": (
        "product/product-integration-acceptance.json"
    ),
}
SOURCE_FILES = frozenset(SOURCE_PATHS.values())
PRELIMINARY_FILES = frozenset({*SOURCE_FILES, DECISION_PATH, INDEX_PATH})
FINAL_FILES = frozenset(
    {
        *PRELIMINARY_FILES,
        RELEASE_ATTESTATION_PATH,
        RELEASE_VERIFICATION_PATH,
    }
)
SOURCE_LIMITS = {path: MAX_ARTIFACT_BYTES for path in SOURCE_FILES}
SOURCE_LIMITS[SOURCE_PATHS["evidence_attestation"]] = MAX_KEY_BYTES
SOURCE_LIMITS[SOURCE_PATHS["evidence_attestation_verification"]] = MAX_KEY_BYTES

DOSSIER_FIELDS = {
    "schema_version",
    "generated_at_utc",
    "phase",
    "status",
    "authorization",
    "candidate",
    "profile",
    "source_revision",
    "artifact_revision",
    "release_revision",
    "source_tree_sha256",
    "release_decision_path",
    "release_decision_sha256",
    "release_decision",
    "evidence_trust",
    "pilot_signoff_trust",
    "release_trust",
    "assurance",
    "inventory",
}
TRUST_FIELDS = {
    "external_public_key_required",
    "public_key_supplied",
    "expected_key_id",
    "verified_key_id",
    "verified_public_key_spki_sha256",
}
PILOT_SIGNOFF_TRUST_FIELDS = {
    "external_trust_policy_required",
    "trust_policy_embedded",
    "trust_policy_supplied",
    "expected_trust_policy_sha256",
    "verification_report_trust_policy_sha256",
    "verification_report_signer_spki_sha256",
    "verification_report_signer_spki_set_sha256",
}
ASSURANCE_FIELDS = {
    "semantic_authority",
    "terminal_unsigned_index",
    "index_self_hash_included",
    "inventory_is_exact",
    "inventory_is_acyclic",
    "public_keys_embedded",
    "release_operator_attestation_verified",
    "independent_reproduction_proven_by_dossier",
    "compiler_trust_proven_by_dossier",
    "candidate_blind_build_proven_by_dossier",
    "hermetic_build_proven_by_dossier",
    "pilot_signoffs_generated",
    "product_acceptance_generated",
}
INVENTORY_FIELDS = {"path", "required", "present", "bytes", "sha256"}
DECISION_STATUS_FIELDS = (
    "artifact_integrity",
    "runtime_safety",
    "contract_compatibility",
    "product_integration",
    "privacy_security",
    "operational_readiness",
    "model_readiness",
    "relay_readiness",
    "human_signoffs",
)


class DossierError(Exception):
    """The supplied dossier or evidence is malformed or unsafe."""


class DossierBlocked(DossierError):
    """A required external or terminal input is absent."""


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _strict_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON value is forbidden: {value}")
    return parsed


def strict_json_loads(raw: bytes) -> object:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_strict_json_object,
        parse_constant=_reject_json_constant,
        parse_float=_strict_json_float,
    )


def _json_bytes(payload: dict) -> bytes:
    return (
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")


def _validate_utc(value: object) -> None:
    if not isinstance(value, str):
        raise DossierError("dossier generated_at_utc is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise DossierError("dossier generated_at_utc is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise DossierError("dossier generated_at_utc must be UTC")


def _safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    candidate = PurePosixPath(value)
    return (
        not candidate.is_absolute()
        and value == candidate.as_posix()
        and all(part not in ("", ".", "..") for part in candidate.parts)
    )


def _read_descriptor(descriptor: int, maximum: int, label: str) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise DossierError(f"{label} must be a regular file")
    if before.st_nlink != 1:
        raise DossierError(f"{label} must not be a hard link")
    if not 1 <= before.st_size <= maximum:
        raise DossierError(
            f"{label} must be nonempty and no larger than {maximum} bytes"
        )
    chunks: list[bytes] = []
    observed = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum - observed + 1))
        if not chunk:
            break
        observed += len(chunk)
        if observed > maximum:
            raise DossierError(f"{label} exceeds its size limit")
        chunks.append(chunk)
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
    if observed != before.st_size or identity_before != identity_after:
        raise DossierError(f"{label} changed while it was being read")
    return b"".join(chunks)


def _open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY
    for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def read_stable_regular_file(path: Path, maximum: int, label: str) -> bytes:
    try:
        descriptor = os.open(path, _open_flags())
    except FileNotFoundError as error:
        raise DossierBlocked(f"{label} is missing") from error
    except OSError as error:
        raise DossierError(
            f"{label} is inaccessible, is a symlink, or is not a regular file"
        ) from error
    try:
        return _read_descriptor(descriptor, maximum, label)
    finally:
        os.close(descriptor)


def read_supplied_regular_file(path: Path, maximum: int, label: str) -> bytes:
    """Read a caller-supplied path; omission and a broken supplied path differ."""

    try:
        return read_stable_regular_file(path, maximum, label)
    except DossierBlocked as error:
        raise DossierError(f"supplied {label} is missing") from error


def _expected_children(files: frozenset[str]) -> dict[str, dict[str, bool]]:
    result: dict[str, dict[str, bool]] = {"": {}}
    for relative in files:
        parts = PurePosixPath(relative).parts
        prefix = ""
        for index, part in enumerate(parts):
            is_file = index == len(parts) - 1
            result.setdefault(prefix, {})[part] = is_file
            if not is_file:
                prefix = f"{prefix}/{part}" if prefix else part
                result.setdefault(prefix, {})
    return result


def _snapshot_fixed_tree_descriptor(
    root_descriptor: int,
    allowed_files: frozenset[str],
    limits: dict[str, int],
    label: str,
) -> dict[str, bytes]:
    """Read a fixed tree through pinned no-follow directory descriptors."""

    children = _expected_children(allowed_files)
    snapshots: dict[str, bytes] = {}

    def walk(directory_descriptor: int, prefix: str) -> None:
        directory_before = os.fstat(directory_descriptor)
        expected = children[prefix]
        try:
            entries = list(os.scandir(directory_descriptor))
        except OSError as error:
            raise DossierError(f"cannot enumerate {label}") from error
        for entry in entries:
            if entry.name not in expected:
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                raise DossierError(f"{label} contains an extra path: {relative}")
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            expected_file = expected[entry.name]
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise DossierError(f"cannot inspect {label} path: {relative}") from error
            if expected_file:
                if not stat.S_ISREG(metadata.st_mode):
                    raise DossierError(
                        f"{label} path must be a regular file, not a symlink or FIFO: "
                        f"{relative}"
                    )
                try:
                    descriptor = os.open(
                        entry.name,
                        _open_flags(),
                        dir_fd=directory_descriptor,
                    )
                except OSError as error:
                    raise DossierError(
                        f"cannot safely open {label} path: {relative}"
                    ) from error
                try:
                    opened = os.fstat(descriptor)
                    if (opened.st_dev, opened.st_ino) != (
                        metadata.st_dev,
                        metadata.st_ino,
                    ):
                        raise DossierError(
                            f"{label} path changed before it could be read: {relative}"
                        )
                    snapshots[relative] = _read_descriptor(
                        descriptor,
                        limits.get(relative, MAX_ARTIFACT_BYTES),
                        f"{label} path {relative}",
                    )
                    observed_after = os.stat(
                        entry.name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        observed_after.st_dev,
                        observed_after.st_ino,
                        observed_after.st_mode,
                        observed_after.st_nlink,
                        observed_after.st_size,
                        observed_after.st_mtime_ns,
                        observed_after.st_ctime_ns,
                    ) != (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_mode,
                        opened.st_nlink,
                        opened.st_size,
                        opened.st_mtime_ns,
                        opened.st_ctime_ns,
                    ):
                        raise DossierError(
                            f"{label} path changed after it was read: {relative}"
                        )
                finally:
                    os.close(descriptor)
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                raise DossierError(
                    f"{label} path must be a real directory: {relative}"
                )
            try:
                child_descriptor = os.open(
                    entry.name,
                    _open_flags(directory=True),
                    dir_fd=directory_descriptor,
                )
            except OSError as error:
                raise DossierError(
                    f"cannot safely open {label} directory: {relative}"
                ) from error
            try:
                opened = os.fstat(child_descriptor)
                if (opened.st_dev, opened.st_ino) != (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    raise DossierError(
                        f"{label} directory changed while it was opened: {relative}"
                    )
                walk(child_descriptor, relative)
            finally:
                os.close(child_descriptor)
        try:
            names_after = sorted(entry.name for entry in os.scandir(directory_descriptor))
        except OSError as error:
            raise DossierError(f"cannot re-enumerate {label}") from error
        directory_after = os.fstat(directory_descriptor)
        identity_before = (
            directory_before.st_dev,
            directory_before.st_ino,
            directory_before.st_mtime_ns,
            directory_before.st_ctime_ns,
        )
        identity_after = (
            directory_after.st_dev,
            directory_after.st_ino,
            directory_after.st_mtime_ns,
            directory_after.st_ctime_ns,
        )
        if names_after != sorted(entry.name for entry in entries) or (
            identity_after != identity_before
        ):
            raise DossierError(f"{label} changed while it was being read")

    metadata = os.fstat(root_descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise DossierError(f"{label} must be a directory")
    walk(root_descriptor, "")
    return snapshots


def snapshot_fixed_tree(
    root: Path,
    allowed_files: frozenset[str],
    limits: dict[str, int],
    label: str,
) -> dict[str, bytes]:
    try:
        root_descriptor = os.open(root, _open_flags(directory=True))
    except OSError as error:
        raise DossierError(f"{label} must be a real directory: {root}") from error
    try:
        return _snapshot_fixed_tree_descriptor(
            root_descriptor, allowed_files, limits, label
        )
    finally:
        os.close(root_descriptor)


def _source_missing(snapshots: dict[str, bytes]) -> list[str]:
    return sorted(SOURCE_FILES - snapshots.keys())


def _source_contains_invalid_json(snapshots: dict[str, bytes]) -> bool:
    for path in SOURCE_FILES & snapshots.keys():
        try:
            payload = strict_json_loads(snapshots[path])
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return True
        if not isinstance(payload, dict):
            return True
    return False


def _validate_expected_key_id(value: str | None, label: str) -> bool:
    if value is None:
        return False
    if not release_decision.crypto_support.safe_key_id(value):
        raise DossierError(f"{label} expected key_id is malformed")
    return True


def _validate_expected_sha256(value: str | None, label: str) -> bool:
    if value is None:
        return False
    if not release_decision.lowercase_sha256(value):
        raise DossierError(f"{label} expected SHA-256 is malformed")
    return True


def _safe_ascii_identifier(value: object, maximum: int = 128) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and 1 <= len(value) <= maximum
        and all(character.isalnum() or character in "_.@-" for character in value)
    )


def _load_pilot_signoff_verification(raw: bytes) -> dict:
    try:
        payload = strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise DossierError("pilot signoff verification is invalid JSON") from error
    if (
        not isinstance(payload, dict)
        or set(payload) != PILOT_SIGNOFF_VERIFICATION_FIELDS
        or payload.get("schema_version")
        != PILOT_SIGNOFF_VERIFICATION_SCHEMA_VERSION
        or payload.get("status") not in ("pass", "blocked", "fail")
        or not release_decision.lowercase_sha256(payload.get("trust_policy_sha256"))
        or not _safe_ascii_identifier(payload.get("policy_id"))
        or not isinstance(payload.get("policy_epoch"), int)
        or isinstance(payload.get("policy_epoch"), bool)
        or payload["policy_epoch"] <= 0
        or payload.get("signature_algorithm") != PILOT_SIGNOFF_SIGNATURE_ALGORITHM
        or payload.get("required_review_areas") != list(PILOT_REQUIRED_REVIEW_AREAS)
        or not isinstance(payload.get("verified_signoff_count"), int)
        or isinstance(payload.get("verified_signoff_count"), bool)
        or not isinstance(payload.get("distinct_signer_count"), int)
        or isinstance(payload.get("distinct_signer_count"), bool)
        or not release_decision.lowercase_sha256(payload.get("signoff_set_sha256"))
        or not release_decision.lowercase_sha256(payload.get("signer_spki_set_sha256"))
    ):
        raise DossierError("pilot signoff verification fields are invalid")
    signers = payload.get("signer_spki_sha256")
    attestations = payload.get("attestations")
    if (
        not isinstance(signers, list)
        or len(signers) != len(PILOT_REQUIRED_REVIEW_AREAS)
        or any(not release_decision.lowercase_sha256(value) for value in signers)
        or len(set(signers)) != len(signers)
        or not isinstance(attestations, list)
        or len(attestations) != len(PILOT_REQUIRED_REVIEW_AREAS)
        or any(not isinstance(value, dict) for value in attestations)
    ):
        raise DossierError("pilot signoff verification signer set is invalid")
    release_revision = payload.get("release_revision")
    if (
        not isinstance(release_revision, str)
        or len(release_revision) != 40
        or any(character not in "0123456789abcdef" for character in release_revision)
    ):
        raise DossierError("pilot signoff verification release revision is invalid")
    if payload["status"] == "pass" and (
        payload["verified_signoff_count"] != len(PILOT_REQUIRED_REVIEW_AREAS)
        or payload["distinct_signer_count"] != len(PILOT_REQUIRED_REVIEW_AREAS)
    ):
        raise DossierError("passing pilot signoff verification is incomplete")
    return payload


def _load_pilot_signoff_trust_policy(raw: bytes) -> dict:
    try:
        payload = strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise DossierError("pilot signoff trust policy is invalid JSON") from error
    try:
        pilot_signoff_verification.validate_trust_policy(payload)
    except pilot_signoff_verification.PilotSignoffError as error:
        raise DossierError("pilot signoff trust policy fields are invalid") from error
    return payload


def _pilot_policy_signer_spki(policy: dict) -> list[str]:
    # RFC 8410 SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 public key.
    prefix = bytes.fromhex("302a300506032b6570032100")
    return [
        sha256(prefix + bytes.fromhex(role["public_key_hex"])).hexdigest()
        for role in policy["roles"]
    ]


def _validate_pilot_signoff_trust(
    verification_raw: bytes,
    trust_policy_raw: bytes,
    expected_trust_policy_sha256: str,
    expected_release_revision: str,
    *,
    require_pass: bool = True,
) -> dict:
    _validate_expected_sha256(
        expected_trust_policy_sha256, "pilot signoff trust policy"
    )
    report = _load_pilot_signoff_verification(verification_raw)
    policy = _load_pilot_signoff_trust_policy(trust_policy_raw)
    try:
        pilot_signoff_verification.validate_verification_report(
            report,
            policy,
            expected_trust_policy_sha256,
            expected_release_revision,
        )
    except pilot_signoff_verification.PilotSignoffError as error:
        raise DossierError(
            "pilot signoff verification does not match its external trust policy or release"
        ) from error
    if require_pass and report["status"] != "pass":
        raise DossierError(
            "only a passing pilot signoff verification may authorize a final dossier"
        )
    return report


def _external_file_optional(
    path: Path | None, maximum: int, label: str
) -> tuple[bytes | None, bool]:
    if path is None:
        return None, False
    return read_supplied_regular_file(path, maximum, label), True


def _write_private_file(path: Path, raw: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


@contextmanager
def _materialized_inputs(
    snapshots: dict[str, bytes],
    evidence_public_key: bytes | None = None,
    release_public_key: bytes | None = None,
    release_attestation: bytes | None = None,
    pilot_signoff_trust_policy: bytes | None = None,
):
    with tempfile.TemporaryDirectory(prefix="aura-release-dossier-inputs-") as directory:
        root = Path(directory)
        for relative, raw in snapshots.items():
            _write_private_file(root / relative, raw)
        external: dict[str, Path | None] = {
            "evidence_public_key": None,
            "release_public_key": None,
            "release_attestation": None,
            "pilot_signoff_trust_policy": None,
        }
        for name, raw in (
            ("evidence_public_key", evidence_public_key),
            ("release_public_key", release_public_key),
            ("release_attestation", release_attestation),
            ("pilot_signoff_trust_policy", pilot_signoff_trust_policy),
        ):
            if raw is not None:
                path = root / "_external" / f"{name}.bin"
                _write_private_file(path, raw)
                external[name] = path
        yield root, external


def _decision_paths(
    root: Path,
    present_paths: set[str],
    evidence_public_key: Path | None,
    expected_evidence_key_id: str | None,
    pilot_signoff_trust_policy: Path | None = None,
    expected_pilot_signoff_trust_policy_sha256: str | None = None,
) -> dict[str, str | None]:
    paths = {
        field: (root / relative).as_posix() if relative in present_paths else None
        for field, relative in SOURCE_PATHS.items()
    }
    paths["evidence_public_key"] = (
        evidence_public_key.as_posix() if evidence_public_key is not None else None
    )
    paths["expected_evidence_key_id"] = expected_evidence_key_id
    paths["pilot_signoff_trust_policy"] = (
        pilot_signoff_trust_policy.as_posix()
        if pilot_signoff_trust_policy is not None
        else None
    )
    paths["expected_pilot_signoff_trust_policy_sha256"] = (
        expected_pilot_signoff_trust_policy_sha256
    )
    return paths


def _load_decision_from_snapshot(
    snapshots: dict[str, bytes],
    evidence_public_key: bytes | None,
    expected_evidence_key_id: str | None,
    pilot_signoff_trust_policy: bytes | None,
    expected_pilot_signoff_trust_policy_sha256: str | None,
) -> tuple[dict, bytes]:
    with _materialized_inputs(
        snapshots,
        evidence_public_key=evidence_public_key,
        pilot_signoff_trust_policy=pilot_signoff_trust_policy,
    ) as (root, external):
        decision_path = root / DECISION_PATH
        raw, decision = release_decision.load_decision(decision_path)
        release_decision.verify_decision_evidence(
            decision,
            _decision_paths(
                root,
                set(snapshots),
                external["evidence_public_key"],
                expected_evidence_key_id,
                external["pilot_signoff_trust_policy"],
                expected_pilot_signoff_trust_policy_sha256,
            ),
        )
    return decision, raw


def _create_decision(
    snapshots: dict[str, bytes],
    candidate_revision: str,
    runtime_version: str,
    evidence_public_key: bytes | None,
    expected_evidence_key_id: str | None,
    pilot_signoff_trust_policy: bytes | None,
    expected_pilot_signoff_trust_policy_sha256: str | None,
) -> dict:
    with _materialized_inputs(
        snapshots,
        evidence_public_key=evidence_public_key,
        pilot_signoff_trust_policy=pilot_signoff_trust_policy,
    ) as (root, external):
        return release_decision.create_decision(
            candidate_revision,
            runtime_version,
            release_decision.PROFILE,
            _decision_paths(
                root,
                set(snapshots),
                external["evidence_public_key"],
                expected_evidence_key_id,
                external["pilot_signoff_trust_policy"],
                expected_pilot_signoff_trust_policy_sha256,
            ),
        )


def _inventory(
    snapshots: dict[str, bytes], phase: str
) -> list[dict[str, object]]:
    expected = (
        (FINAL_FILES if phase == "final" else PRELIMINARY_FILES) - {INDEX_PATH}
    )
    inventory = []
    for path in sorted(expected):
        raw = snapshots.get(path)
        inventory.append(
            {
                "path": path,
                "required": True,
                "present": raw is not None,
                "bytes": len(raw) if raw is not None else None,
                "sha256": sha256(raw).hexdigest() if raw is not None else None,
            }
        )
    return inventory


def _preliminary_status(
    decision: dict,
    snapshots: dict[str, bytes],
    evidence_public_key_supplied: bool,
    expected_evidence_key_id_supplied: bool,
    malformed_external_key: bool,
    invalid_pilot_signoff_trust: bool,
) -> str:
    if (
        malformed_external_key
        or invalid_pilot_signoff_trust
        or _source_contains_invalid_json(snapshots)
    ):
        return "fail"
    if any(decision[field] == "fail" for field in DECISION_STATUS_FIELDS):
        return "fail"
    if (
        _source_missing(snapshots)
        or not evidence_public_key_supplied
        or not expected_evidence_key_id_supplied
    ):
        return "blocked"
    return "blocked"


def _build_dossier(
    snapshots: dict[str, bytes],
    decision: dict,
    *,
    phase: str,
    generated_at_utc: str,
    status: str,
    evidence_public_key_supplied: bool,
    expected_evidence_key_id: str | None,
    pilot_signoff_trust_policy_supplied: bool,
    expected_pilot_signoff_trust_policy_sha256: str | None,
    pilot_signoff_report: dict | None,
    release_report: dict | None = None,
    expected_release_key_id: str | None = None,
) -> dict:
    if phase not in ("preliminary", "final"):
        raise DossierError("dossier phase is invalid")
    decision_raw = snapshots.get(DECISION_PATH)
    if decision_raw is None:
        raise DossierError("release decision is absent from the dossier")
    final = phase == "final"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated_at_utc,
        "phase": phase,
        "status": status,
        "authorization": "go" if final else "blocked",
        "candidate": decision["candidate"],
        "profile": decision["profile"],
        "source_revision": decision["source_revision"],
        "artifact_revision": decision["artifact_revision"],
        "release_revision": decision["release_revision"],
        "source_tree_sha256": decision["source_tree_sha256"],
        "release_decision_path": DECISION_PATH,
        "release_decision_sha256": sha256(decision_raw).hexdigest(),
        "release_decision": decision["decision"],
        "evidence_trust": {
            "external_public_key_required": True,
            "public_key_supplied": evidence_public_key_supplied,
            "expected_key_id": expected_evidence_key_id,
            "verified_key_id": decision["evidence_signer_key_id"],
            "verified_public_key_spki_sha256": decision[
                "evidence_signer_spki_sha256"
            ],
        },
        "pilot_signoff_trust": {
            "external_trust_policy_required": True,
            "trust_policy_embedded": False,
            "trust_policy_supplied": pilot_signoff_trust_policy_supplied,
            "expected_trust_policy_sha256": (
                expected_pilot_signoff_trust_policy_sha256
            ),
            "verification_report_trust_policy_sha256": (
                pilot_signoff_report["trust_policy_sha256"]
                if pilot_signoff_report is not None
                else None
            ),
            "verification_report_signer_spki_sha256": (
                pilot_signoff_report["signer_spki_sha256"]
                if pilot_signoff_report is not None
                else None
            ),
            "verification_report_signer_spki_set_sha256": (
                pilot_signoff_report["signer_spki_set_sha256"]
                if pilot_signoff_report is not None
                else None
            ),
        },
        "release_trust": (
            {
                "external_public_key_required": True,
                "public_key_supplied": True,
                "expected_key_id": expected_release_key_id,
                "verified_key_id": release_report["key_id"],
                "verified_public_key_spki_sha256": release_report[
                    "public_key_spki_sha256"
                ],
            }
            if release_report is not None
            else None
        ),
        "assurance": {
            "semantic_authority": "ci.release_decision",
            "terminal_unsigned_index": True,
            "index_self_hash_included": False,
            "inventory_is_exact": True,
            "inventory_is_acyclic": True,
            "public_keys_embedded": False,
            "release_operator_attestation_verified": final,
            "independent_reproduction_proven_by_dossier": False,
            "compiler_trust_proven_by_dossier": False,
            "candidate_blind_build_proven_by_dossier": False,
            "hermetic_build_proven_by_dossier": False,
            "pilot_signoffs_generated": False,
            "product_acceptance_generated": False,
        },
        "inventory": _inventory(snapshots, phase),
    }


def _validate_dossier_shape(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != DOSSIER_FIELDS:
        raise DossierError("dossier fields do not match v2")
    _validate_utc(payload.get("generated_at_utc"))
    phase = payload.get("phase")
    if (
        payload.get("schema_version") != SCHEMA_VERSION
        or phase not in ("preliminary", "final")
        or payload.get("status") not in ("pass", "blocked", "fail")
        or payload.get("authorization") not in ("go", "blocked")
        or payload.get("release_decision_path") != DECISION_PATH
        or payload.get("release_decision") not in ("go", "no-go")
        or not release_decision.lowercase_sha256(
            payload.get("release_decision_sha256")
        )
    ):
        raise DossierError("dossier identity or state is invalid")
    for field in ("evidence_trust",):
        trust = payload.get(field)
        if not isinstance(trust, dict) or set(trust) != TRUST_FIELDS:
            raise DossierError(f"dossier {field} is invalid")
        _validate_trust(trust, field)
    pilot_signoff_trust = payload.get("pilot_signoff_trust")
    if (
        not isinstance(pilot_signoff_trust, dict)
        or set(pilot_signoff_trust) != PILOT_SIGNOFF_TRUST_FIELDS
    ):
        raise DossierError("dossier pilot_signoff_trust is invalid")
    _validate_pilot_signoff_trust_metadata(pilot_signoff_trust)
    release_trust = payload.get("release_trust")
    if release_trust is not None and (
        not isinstance(release_trust, dict) or set(release_trust) != TRUST_FIELDS
    ):
        raise DossierError("dossier release_trust is invalid")
    if release_trust is not None:
        _validate_trust(release_trust, "release_trust")
    assurance = payload.get("assurance")
    if not isinstance(assurance, dict) or set(assurance) != ASSURANCE_FIELDS:
        raise DossierError("dossier assurance boundaries are invalid")
    fixed_assurance = {
        "semantic_authority": "ci.release_decision",
        "terminal_unsigned_index": True,
        "index_self_hash_included": False,
        "inventory_is_exact": True,
        "inventory_is_acyclic": True,
        "public_keys_embedded": False,
        "independent_reproduction_proven_by_dossier": False,
        "compiler_trust_proven_by_dossier": False,
        "candidate_blind_build_proven_by_dossier": False,
        "hermetic_build_proven_by_dossier": False,
        "pilot_signoffs_generated": False,
        "product_acceptance_generated": False,
    }
    if any(
        type(assurance.get(field)) is not type(value)
        or assurance.get(field) != value
        for field, value in fixed_assurance.items()
    ):
        raise DossierError("dossier assurance boundaries are invalid")
    if not isinstance(
        assurance.get("release_operator_attestation_verified"), bool
    ):
        raise DossierError("dossier assurance boundary type is invalid")
    inventory = payload.get("inventory")
    if not isinstance(inventory, list):
        raise DossierError("dossier inventory is invalid")
    paths: list[str] = []
    for entry in inventory:
        if not isinstance(entry, dict) or set(entry) != INVENTORY_FIELDS:
            raise DossierError("dossier inventory entry is invalid")
        path = entry.get("path")
        if not _safe_relative_path(path) or path == INDEX_PATH:
            raise DossierError("dossier inventory path is unsafe or cyclic")
        present = entry.get("present")
        if entry.get("required") is not True or not isinstance(present, bool):
            raise DossierError("dossier inventory state type is invalid")
        if present:
            size = entry.get("bytes")
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or size <= 0
                or not release_decision.lowercase_sha256(entry.get("sha256"))
            ):
                raise DossierError("dossier inventory identity is invalid")
        elif entry.get("bytes") is not None or entry.get("sha256") is not None:
            raise DossierError("missing dossier inventory entry has an identity")
        paths.append(path)
    if paths != sorted(set(paths)):
        raise DossierError("dossier inventory paths are not exact and ordered")
    return payload


def _validate_trust(trust: dict, label: str) -> None:
    if trust.get("external_public_key_required") is not True or not isinstance(
        trust.get("public_key_supplied"), bool
    ):
        raise DossierError(f"dossier {label} presence state is invalid")
    for field in ("expected_key_id", "verified_key_id"):
        value = trust.get(field)
        if value is not None and (
            not isinstance(value, str)
            or not release_decision.crypto_support.safe_key_id(value)
        ):
            raise DossierError(f"dossier {label} {field} is invalid")
    digest = trust.get("verified_public_key_spki_sha256")
    if digest is not None and not release_decision.lowercase_sha256(digest):
        raise DossierError(f"dossier {label} SPKI identity is invalid")


def _validate_pilot_signoff_trust_metadata(trust: dict) -> None:
    if (
        trust.get("external_trust_policy_required") is not True
        or trust.get("trust_policy_embedded") is not False
        or not isinstance(trust.get("trust_policy_supplied"), bool)
    ):
        raise DossierError("dossier pilot signoff trust presence is invalid")
    for field in (
        "expected_trust_policy_sha256",
        "verification_report_trust_policy_sha256",
        "verification_report_signer_spki_set_sha256",
    ):
        value = trust.get(field)
        if value is not None and not release_decision.lowercase_sha256(value):
            raise DossierError(f"dossier pilot signoff trust {field} is invalid")
    signers = trust.get("verification_report_signer_spki_sha256")
    if signers is not None and (
        not isinstance(signers, list)
        or len(signers) != len(PILOT_REQUIRED_REVIEW_AREAS)
        or any(not release_decision.lowercase_sha256(value) for value in signers)
        or len(set(signers)) != len(signers)
    ):
        raise DossierError("dossier pilot signoff signer identities are invalid")
    reported_policy = trust.get("verification_report_trust_policy_sha256")
    reported_set = trust.get("verification_report_signer_spki_set_sha256")
    if reported_policy is None:
        if signers is not None or reported_set is not None:
            raise DossierError("dossier pilot signoff report identity is incomplete")
    elif signers is None or reported_set is None:
        raise DossierError("dossier pilot signoff report identity is incomplete")


def _load_index(snapshots: dict[str, bytes]) -> dict:
    raw = snapshots.get(INDEX_PATH)
    if raw is None:
        raise DossierBlocked("dossier index is missing")
    try:
        payload = strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise DossierError("dossier index is invalid JSON") from error
    return _validate_dossier_shape(payload)


def _bundle_limits() -> dict[str, int]:
    limits = dict(SOURCE_LIMITS)
    limits[DECISION_PATH] = MAX_ARTIFACT_BYTES
    limits[RELEASE_ATTESTATION_PATH] = MAX_KEY_BYTES
    limits[RELEASE_VERIFICATION_PATH] = MAX_KEY_BYTES
    limits[INDEX_PATH] = MAX_INDEX_BYTES
    return limits


def _validate_phase_layout(snapshots: dict[str, bytes], phase: str) -> None:
    actual = set(snapshots)
    if phase == "preliminary":
        if not {DECISION_PATH, INDEX_PATH} <= actual:
            raise DossierBlocked("preliminary dossier lacks its decision or index")
        if actual - PRELIMINARY_FILES:
            raise DossierError("preliminary dossier contains final-only files")
        return
    missing = FINAL_FILES - actual
    if missing:
        raise DossierBlocked(
            "final dossier is incomplete: " + ", ".join(sorted(missing))
        )


def _assert_expected_dossier(payload: dict, expected: dict) -> None:
    if _json_bytes(payload) != _json_bytes(expected):
        raise DossierError(
            "dossier index does not exactly match its release decision and inventory"
        )


def _paths_overlap(first: Path, second: Path) -> bool:
    first_resolved = first.resolve(strict=False)
    second_resolved = second.resolve(strict=False)
    return (
        first_resolved == second_resolved
        or first_resolved in second_resolved.parents
        or second_resolved in first_resolved.parents
    )


@contextmanager
def _frozen_output_parent(output: Path):
    """Pin the direct output parent and reject a symlink at that boundary."""

    if output.name in ("", ".", ".."):
        raise DossierError("output path is invalid")
    parent_path = Path(os.path.abspath(output.parent))
    try:
        before = os.lstat(parent_path)
    except FileNotFoundError as error:
        raise DossierError("output parent must already exist") from error
    except OSError as error:
        raise DossierError("output parent is inaccessible") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise DossierError("output parent must be a real, non-symlink directory")
    try:
        descriptor = os.open(parent_path, _open_flags(directory=True))
    except OSError as error:
        raise DossierError("output parent cannot be safely opened") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise DossierError("output parent changed while it was being opened")
        try:
            resolved_parent = parent_path.resolve(strict=True)
            resolved = resolved_parent.stat()
        except OSError as error:
            raise DossierError("output parent cannot be resolved safely") from error
        if (resolved.st_dev, resolved.st_ino) != (opened.st_dev, opened.st_ino):
            raise DossierError("output parent resolution changed during validation")
        yield descriptor, parent_path, resolved_parent, output.name
    finally:
        os.close(descriptor)


def _assert_parent_still_bound(descriptor: int, parent_path: Path) -> None:
    opened = os.fstat(descriptor)
    try:
        observed = os.lstat(parent_path)
    except OSError as error:
        raise DossierError("output parent changed before publication") from error
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or (observed.st_dev, observed.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise DossierError("output parent changed before publication")


def _entry_exists(directory_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _assert_entry_matches_descriptor(
    directory_descriptor: int,
    name: str,
    opened_descriptor: int,
    *,
    directory: bool,
) -> None:
    try:
        observed = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise DossierError("published output name is inaccessible") from error
    opened = os.fstat(opened_descriptor)
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_kind(observed.st_mode)
        or not expected_kind(opened.st_mode)
        or (observed.st_dev, observed.st_ino) != (opened.st_dev, opened.st_ino)
        or (not directory and (observed.st_nlink != 1 or opened.st_nlink != 1))
    ):
        raise DossierError("published output was replaced during publication")


def _ensure_disjoint_output(
    parent_descriptor: int,
    resolved_parent: Path,
    target_name: str,
    protected: list[Path],
) -> None:
    target = resolved_parent / target_name
    for path in protected:
        if _paths_overlap(target, path):
            raise DossierError("output must not alias, contain, or overwrite an input")
    if _entry_exists(parent_descriptor, target_name):
        raise DossierError("output must be fresh and must not overwrite an existing path")


def _rename_noreplace_at(
    parent_descriptor: int, source_name: str, target_name: str
) -> None:
    source_bytes = os.fsencode(source_name)
    target_bytes = os.fsencode(target_name)
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(library, "renameatx_np"):
        renameatx = library.renameatx_np
        renameatx.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameatx.restype = ctypes.c_int
        result = renameatx(
            parent_descriptor,
            source_bytes,
            parent_descriptor,
            target_bytes,
            0x00000004,  # RENAME_EXCL
        )
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        renameat2 = library.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            parent_descriptor,
            source_bytes,
            parent_descriptor,
            target_bytes,
            1,
        )
    else:
        raise DossierError(
            "this platform lacks a no-replace atomic publish primitive"
        )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in (errno.EEXIST, errno.ENOTEMPTY):
            raise DossierError("output appeared during atomic publication")
        raise OSError(error_number, os.strerror(error_number), target_name)


def _create_temporary_directory_at(
    parent_descriptor: int, target_name: str
) -> tuple[str, int]:
    for _attempt in range(128):
        name = f".{target_name}.{secrets.token_hex(12)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        try:
            descriptor = os.open(
                name,
                _open_flags(directory=True),
                dir_fd=parent_descriptor,
            )
        except Exception:
            raise
        return name, descriptor
    raise DossierError("cannot allocate a fresh temporary output directory")


def _open_child_directory(parent_descriptor: int, name: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
    except FileExistsError:
        pass
    try:
        descriptor = os.open(
            name,
            _open_flags(directory=True),
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        raise DossierError("bundle directory cannot be opened safely") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise DossierError("bundle path component is not a directory")
    return descriptor


def _write_private_file_at(
    root_descriptor: int, relative: str, raw: bytes
) -> None:
    parts = PurePosixPath(relative).parts
    current = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            child = _open_child_directory(current, part)
            os.fsync(current)
            os.close(current)
            current = child
        try:
            descriptor = os.open(
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
            raise DossierError("bundle file cannot be created safely") from error
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        os.fsync(current)
    finally:
        os.close(current)


def _fresh_temporary_file_at(
    parent_descriptor: int, target_name: str
) -> tuple[str, int]:
    for _attempt in range(128):
        name = f".{target_name}.{secrets.token_hex(12)}"
        try:
            descriptor = os.open(
                name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileExistsError:
            continue
        return name, descriptor
    raise DossierError("cannot allocate a fresh temporary output file")


def publish_bundle(output: Path, files: dict[str, bytes], protected: list[Path]) -> None:
    with _frozen_output_parent(output) as (
        parent_descriptor,
        parent_path,
        resolved_parent,
        target_name,
    ):
        _ensure_disjoint_output(
            parent_descriptor, resolved_parent, target_name, protected
        )
        temporary_name, temporary_descriptor = _create_temporary_directory_at(
            parent_descriptor, target_name
        )
        try:
            for relative in sorted(files):
                if not _safe_relative_path(relative):
                    raise DossierError("refusing to publish an unsafe bundle path")
                _write_private_file_at(
                    temporary_descriptor, relative, files[relative]
                )
            os.fsync(temporary_descriptor)
            _assert_parent_still_bound(parent_descriptor, parent_path)
            _rename_noreplace_at(
                parent_descriptor, temporary_name, target_name
            )
            _assert_entry_matches_descriptor(
                parent_descriptor,
                target_name,
                temporary_descriptor,
                directory=True,
            )
            limits = {relative: max(1, len(raw)) for relative, raw in files.items()}
            if _snapshot_fixed_tree_descriptor(
                temporary_descriptor,
                frozenset(files),
                limits,
                "published release dossier",
            ) != files:
                raise DossierError(
                    "published release dossier bytes changed during publication"
                )
            os.fsync(parent_descriptor)
            _assert_parent_still_bound(parent_descriptor, parent_path)
            _assert_entry_matches_descriptor(
                parent_descriptor,
                target_name,
                temporary_descriptor,
                directory=True,
            )
        except Exception:
            # Never delete a name after an error. A concurrent writer may have
            # replaced it; retaining a private random staging directory is
            # safer than deleting data that no longer belongs to this call.
            raise
        finally:
            os.close(temporary_descriptor)


def _publish_report(output: Path, raw: bytes, protected: list[Path]) -> None:
    with _frozen_output_parent(output) as (
        parent_descriptor,
        parent_path,
        resolved_parent,
        target_name,
    ):
        _ensure_disjoint_output(
            parent_descriptor, resolved_parent, target_name, protected
        )
        temporary_name, descriptor = _fresh_temporary_file_at(
            parent_descriptor, target_name
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.lseek(descriptor, 0, os.SEEK_SET)
            if _read_descriptor(
                descriptor, max(1, len(raw)), "staged dossier report"
            ) != raw:
                raise DossierError("staged dossier report bytes changed")
            _assert_parent_still_bound(parent_descriptor, parent_path)
            _rename_noreplace_at(
                parent_descriptor, temporary_name, target_name
            )
            _assert_entry_matches_descriptor(
                parent_descriptor,
                target_name,
                descriptor,
                directory=False,
            )
            os.lseek(descriptor, 0, os.SEEK_SET)
            if _read_descriptor(
                descriptor, max(1, len(raw)), "published dossier report"
            ) != raw:
                raise DossierError("published dossier report bytes changed")
            os.fsync(parent_descriptor)
            _assert_parent_still_bound(parent_descriptor, parent_path)
            _assert_entry_matches_descriptor(
                parent_descriptor,
                target_name,
                descriptor,
                directory=False,
            )
        except Exception:
            # As above, do not unlink a potentially swapped staging name.
            try:
                os.fsync(parent_descriptor)
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)


def assemble_dossier(
    root: Path,
    output: Path,
    candidate_revision: str,
    runtime_version: str,
    evidence_public_key_path: Path | None,
    expected_evidence_key_id: str | None,
    pilot_signoff_trust_policy_path: Path | None = None,
    expected_pilot_signoff_trust_policy_sha256: str | None = None,
) -> dict:
    snapshots = snapshot_fixed_tree(
        root, SOURCE_FILES, SOURCE_LIMITS, "release evidence root"
    )
    evidence_key_raw, evidence_key_supplied = _external_file_optional(
        evidence_public_key_path, MAX_KEY_BYTES, "external evidence public key"
    )
    expected_id_supplied = _validate_expected_key_id(
        expected_evidence_key_id, "evidence"
    )
    pilot_policy_raw, pilot_policy_supplied = _external_file_optional(
        pilot_signoff_trust_policy_path,
        MAX_PILOT_SIGNOFF_TRUST_POLICY_BYTES,
        "external pilot signoff trust policy",
    )
    _validate_expected_sha256(
        expected_pilot_signoff_trust_policy_sha256,
        "pilot signoff trust policy",
    )
    pilot_report: dict | None = None
    invalid_pilot_trust = False
    pilot_verification_raw = snapshots.get(
        SOURCE_PATHS["pilot_signoff_verification"]
    )
    if pilot_verification_raw is not None:
        try:
            pilot_report = _load_pilot_signoff_verification(
                pilot_verification_raw
            )
            if (
                pilot_report["status"] == "fail"
                or pilot_report["release_revision"] != candidate_revision
                or (
                    expected_pilot_signoff_trust_policy_sha256 is not None
                    and pilot_report["trust_policy_sha256"]
                    != expected_pilot_signoff_trust_policy_sha256
                )
            ):
                invalid_pilot_trust = True
            if pilot_policy_raw is not None:
                _validate_pilot_signoff_trust(
                    pilot_verification_raw,
                    pilot_policy_raw,
                    (
                        expected_pilot_signoff_trust_policy_sha256
                        or pilot_signoff_verification.trust_policy_sha256(
                            _load_pilot_signoff_trust_policy(pilot_policy_raw)
                        )
                    ),
                    candidate_revision,
                    require_pass=False,
                )
        except DossierError:
            invalid_pilot_trust = True
    malformed_key = False
    if evidence_key_raw is not None:
        try:
            with _materialized_inputs(
                {}, evidence_public_key=evidence_key_raw
            ) as (_root, external):
                release_decision.crypto_support.public_key_der_from_public(
                    external["evidence_public_key"]
                )
        except release_decision.ReleaseDecisionError:
            malformed_key = True
    try:
        decision = _create_decision(
            snapshots,
            candidate_revision,
            runtime_version,
            evidence_key_raw,
            expected_evidence_key_id,
            pilot_policy_raw,
            expected_pilot_signoff_trust_policy_sha256,
        )
    except release_decision.ReleaseDecisionError as error:
        raise DossierError(f"release decision authority rejected the candidate: {error}") from error
    decision_raw = _json_bytes(decision)
    output_files = dict(snapshots)
    output_files[DECISION_PATH] = decision_raw
    status = _preliminary_status(
        decision,
        snapshots,
        evidence_key_supplied,
        expected_id_supplied,
        malformed_key,
        invalid_pilot_trust,
    )
    dossier = _build_dossier(
        output_files,
        decision,
        phase="preliminary",
        generated_at_utc=decision["generated_at_utc"],
        status=status,
        evidence_public_key_supplied=evidence_key_supplied,
        expected_evidence_key_id=expected_evidence_key_id,
        pilot_signoff_trust_policy_supplied=pilot_policy_supplied,
        expected_pilot_signoff_trust_policy_sha256=(
            expected_pilot_signoff_trust_policy_sha256
        ),
        pilot_signoff_report=pilot_report,
    )
    output_files[INDEX_PATH] = _json_bytes(dossier)
    protected = [root]
    if evidence_public_key_path is not None:
        protected.append(evidence_public_key_path)
    if pilot_signoff_trust_policy_path is not None:
        protected.append(pilot_signoff_trust_policy_path)
    publish_bundle(output, output_files, protected)
    return dossier


def _verify_preliminary(
    snapshots: dict[str, bytes],
    dossier: dict,
    evidence_public_key_path: Path | None,
    expected_evidence_key_id: str | None,
    pilot_signoff_trust_policy_path: Path | None,
    expected_pilot_signoff_trust_policy_sha256: str | None,
) -> tuple[dict, bytes]:
    trust = dossier["evidence_trust"]
    if trust["expected_key_id"] != expected_evidence_key_id:
        raise DossierError("external evidence key_id pin does not match the dossier")
    key_raw = None
    if evidence_public_key_path is not None:
        key_raw = read_supplied_regular_file(
            evidence_public_key_path,
            MAX_KEY_BYTES,
            "external evidence public key",
        )
    elif trust["public_key_supplied"] is True:
        raise DossierBlocked("external evidence public key is required")
    elif trust["public_key_supplied"] is not False:
        raise DossierError("dossier evidence trust presence is invalid")
    pilot_trust = dossier["pilot_signoff_trust"]
    if (
        pilot_trust["expected_trust_policy_sha256"]
        != expected_pilot_signoff_trust_policy_sha256
    ):
        raise DossierError(
            "external pilot signoff trust-policy pin does not match the dossier"
        )
    _validate_expected_sha256(
        expected_pilot_signoff_trust_policy_sha256,
        "pilot signoff trust policy",
    )
    pilot_policy_raw = None
    if pilot_signoff_trust_policy_path is not None:
        pilot_policy_raw = read_supplied_regular_file(
            pilot_signoff_trust_policy_path,
            MAX_PILOT_SIGNOFF_TRUST_POLICY_BYTES,
            "external pilot signoff trust policy",
        )
    elif pilot_trust["trust_policy_supplied"] is True:
        raise DossierBlocked("external pilot signoff trust policy is required")
    elif pilot_trust["trust_policy_supplied"] is not False:
        raise DossierError("dossier pilot signoff trust presence is invalid")
    decision, decision_raw = _load_decision_from_snapshot(
        snapshots,
        key_raw,
        expected_evidence_key_id,
        pilot_policy_raw,
        expected_pilot_signoff_trust_policy_sha256,
    )
    malformed_key = False
    if key_raw is not None:
        try:
            with _materialized_inputs({}, evidence_public_key=key_raw) as (
                _root,
                external,
            ):
                release_decision.crypto_support.public_key_der_from_public(
                    external["evidence_public_key"]
                )
        except release_decision.ReleaseDecisionError:
            malformed_key = True
    pilot_report: dict | None = None
    invalid_pilot_trust = False
    pilot_verification_raw = snapshots.get(
        SOURCE_PATHS["pilot_signoff_verification"]
    )
    if pilot_verification_raw is not None:
        try:
            pilot_report = _load_pilot_signoff_verification(
                pilot_verification_raw
            )
            if (
                pilot_report["status"] == "fail"
                or pilot_report["release_revision"] != decision["release_revision"]
                or (
                    expected_pilot_signoff_trust_policy_sha256 is not None
                    and pilot_report["trust_policy_sha256"]
                    != expected_pilot_signoff_trust_policy_sha256
                )
            ):
                invalid_pilot_trust = True
            if pilot_policy_raw is not None:
                _validate_pilot_signoff_trust(
                    pilot_verification_raw,
                    pilot_policy_raw,
                    (
                        expected_pilot_signoff_trust_policy_sha256
                        or pilot_signoff_verification.trust_policy_sha256(
                            _load_pilot_signoff_trust_policy(pilot_policy_raw)
                        )
                    ),
                    decision["release_revision"],
                    require_pass=False,
                )
        except DossierError:
            invalid_pilot_trust = True
    expected_status = _preliminary_status(
        decision,
        snapshots,
        trust["public_key_supplied"],
        expected_evidence_key_id is not None,
        malformed_key,
        invalid_pilot_trust,
    )
    expected = _build_dossier(
        snapshots,
        decision,
        phase="preliminary",
        generated_at_utc=decision["generated_at_utc"],
        status=expected_status,
        evidence_public_key_supplied=trust["public_key_supplied"],
        expected_evidence_key_id=expected_evidence_key_id,
        pilot_signoff_trust_policy_supplied=pilot_trust[
            "trust_policy_supplied"
        ],
        expected_pilot_signoff_trust_policy_sha256=(
            expected_pilot_signoff_trust_policy_sha256
        ),
        pilot_signoff_report=pilot_report,
    )
    _assert_expected_dossier(dossier, expected)
    return decision, decision_raw


def finalize_dossier(
    root: Path,
    output: Path,
    release_attestation_path: Path | None,
    evidence_public_key_path: Path | None,
    expected_evidence_key_id: str | None,
    release_public_key_path: Path | None,
    expected_release_key_id: str | None,
    pilot_signoff_trust_policy_path: Path | None = None,
    expected_pilot_signoff_trust_policy_sha256: str | None = None,
) -> dict:
    snapshots = snapshot_fixed_tree(
        root, FINAL_FILES, _bundle_limits(), "preliminary dossier"
    )
    dossier = _load_index(snapshots)
    _validate_phase_layout(snapshots, dossier["phase"])
    if dossier["phase"] != "preliminary":
        raise DossierError("only a preliminary dossier may be finalized")
    if _source_missing(snapshots):
        raise DossierBlocked("all release evidence is required for finalization")
    if expected_evidence_key_id is None or evidence_public_key_path is None:
        raise DossierBlocked("external evidence trust pin is required")
    if expected_release_key_id is None or release_public_key_path is None:
        raise DossierBlocked("external release trust pin is required")
    if (
        pilot_signoff_trust_policy_path is None
        or expected_pilot_signoff_trust_policy_sha256 is None
    ):
        raise DossierBlocked("external pilot signoff trust-policy pin is required")
    if release_attestation_path is None:
        raise DossierBlocked("release decision attestation is required")
    _validate_expected_key_id(expected_evidence_key_id, "evidence")
    _validate_expected_key_id(expected_release_key_id, "release")
    _validate_expected_sha256(
        expected_pilot_signoff_trust_policy_sha256,
        "pilot signoff trust policy",
    )
    _verify_preliminary(
        snapshots,
        dossier,
        evidence_public_key_path,
        expected_evidence_key_id,
        pilot_signoff_trust_policy_path,
        expected_pilot_signoff_trust_policy_sha256,
    )
    evidence_key_raw = read_supplied_regular_file(
        evidence_public_key_path, MAX_KEY_BYTES, "external evidence public key"
    )
    release_key_raw = read_supplied_regular_file(
        release_public_key_path, MAX_KEY_BYTES, "external release public key"
    )
    release_attestation_raw = read_supplied_regular_file(
        release_attestation_path, MAX_KEY_BYTES, "release decision attestation"
    )
    pilot_policy_raw = read_supplied_regular_file(
        pilot_signoff_trust_policy_path,
        MAX_PILOT_SIGNOFF_TRUST_POLICY_BYTES,
        "external pilot signoff trust policy",
    )
    with _materialized_inputs(
        snapshots,
        evidence_public_key=evidence_key_raw,
        release_public_key=release_key_raw,
        release_attestation=release_attestation_raw,
        pilot_signoff_trust_policy=pilot_policy_raw,
    ) as (materialized, external):
        decision_raw, decision = release_decision.load_decision(
            materialized / DECISION_PATH
        )
        release_decision.verify_decision_evidence(
            decision,
            _decision_paths(
                materialized,
                set(snapshots),
                external["evidence_public_key"],
                expected_evidence_key_id,
                external["pilot_signoff_trust_policy"],
                expected_pilot_signoff_trust_policy_sha256,
            ),
        )
        report = release_decision.verify_decision(
            materialized / DECISION_PATH,
            external["release_attestation"],
            external["release_public_key"],
            expected_release_key_id,
        )
    if decision["decision"] != "go" or report.get("status") != "pass":
        raise DossierError("only a verified GO release decision may be finalized")
    pilot_report = _validate_pilot_signoff_trust(
        snapshots[SOURCE_PATHS["pilot_signoff_verification"]],
        pilot_policy_raw,
        expected_pilot_signoff_trust_policy_sha256,
        decision["release_revision"],
    )
    if hmac.compare_digest(
        report["public_key_spki_sha256"],
        decision["evidence_signer_spki_sha256"],
    ):
        raise DossierError("evidence and release roles must use different keys")
    output_files = {
        path: raw for path, raw in snapshots.items() if path != INDEX_PATH
    }
    output_files[DECISION_PATH] = decision_raw
    output_files[RELEASE_ATTESTATION_PATH] = release_attestation_raw
    output_files[RELEASE_VERIFICATION_PATH] = _json_bytes(report)
    final_dossier = _build_dossier(
        output_files,
        decision,
        phase="final",
        generated_at_utc=decision["generated_at_utc"],
        status="pass",
        evidence_public_key_supplied=True,
        expected_evidence_key_id=expected_evidence_key_id,
        pilot_signoff_trust_policy_supplied=True,
        expected_pilot_signoff_trust_policy_sha256=(
            expected_pilot_signoff_trust_policy_sha256
        ),
        pilot_signoff_report=pilot_report,
        release_report=report,
        expected_release_key_id=expected_release_key_id,
    )
    output_files[INDEX_PATH] = _json_bytes(final_dossier)
    publish_bundle(
        output,
        output_files,
        [
            root,
            evidence_public_key_path,
            release_public_key_path,
            release_attestation_path,
            pilot_signoff_trust_policy_path,
        ],
    )
    return final_dossier


def verify_dossier(
    root: Path,
    evidence_public_key_path: Path | None,
    expected_evidence_key_id: str | None,
    release_public_key_path: Path | None = None,
    expected_release_key_id: str | None = None,
    pilot_signoff_trust_policy_path: Path | None = None,
    expected_pilot_signoff_trust_policy_sha256: str | None = None,
) -> dict:
    snapshots = snapshot_fixed_tree(root, FINAL_FILES, _bundle_limits(), "dossier")
    dossier = _load_index(snapshots)
    phase = dossier["phase"]
    _validate_phase_layout(snapshots, phase)
    if phase == "preliminary":
        decision, _decision_raw = _verify_preliminary(
            snapshots,
            dossier,
            evidence_public_key_path,
            expected_evidence_key_id,
            pilot_signoff_trust_policy_path,
            expected_pilot_signoff_trust_policy_sha256,
        )
        release_report = None
        pilot_signoff_trust_policy_verified = False
    else:
        if evidence_public_key_path is None or expected_evidence_key_id is None:
            raise DossierBlocked("external evidence trust pin is required")
        if release_public_key_path is None or expected_release_key_id is None:
            raise DossierBlocked("external release trust pin is required")
        if (
            pilot_signoff_trust_policy_path is None
            or expected_pilot_signoff_trust_policy_sha256 is None
        ):
            raise DossierBlocked(
                "external pilot signoff trust-policy pin is required"
            )
        _validate_expected_key_id(expected_evidence_key_id, "evidence")
        _validate_expected_key_id(expected_release_key_id, "release")
        _validate_expected_sha256(
            expected_pilot_signoff_trust_policy_sha256,
            "pilot signoff trust policy",
        )
        evidence_key_raw = read_supplied_regular_file(
            evidence_public_key_path, MAX_KEY_BYTES, "external evidence public key"
        )
        release_key_raw = read_supplied_regular_file(
            release_public_key_path, MAX_KEY_BYTES, "external release public key"
        )
        pilot_policy_raw = read_supplied_regular_file(
            pilot_signoff_trust_policy_path,
            MAX_PILOT_SIGNOFF_TRUST_POLICY_BYTES,
            "external pilot signoff trust policy",
        )
        with _materialized_inputs(
            snapshots,
            evidence_public_key=evidence_key_raw,
            release_public_key=release_key_raw,
            pilot_signoff_trust_policy=pilot_policy_raw,
        ) as (materialized, external):
            decision_raw, decision = release_decision.load_decision(
                materialized / DECISION_PATH
            )
            release_decision.verify_decision_evidence(
                decision,
                _decision_paths(
                    materialized,
                    set(snapshots),
                    external["evidence_public_key"],
                    expected_evidence_key_id,
                    external["pilot_signoff_trust_policy"],
                    expected_pilot_signoff_trust_policy_sha256,
                ),
            )
            release_report = release_decision.verify_decision(
                materialized / DECISION_PATH,
                materialized / RELEASE_ATTESTATION_PATH,
                external["release_public_key"],
                expected_release_key_id,
            )
        try:
            copied_report = strict_json_loads(snapshots[RELEASE_VERIFICATION_PATH])
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise DossierError("copied release verification is invalid JSON") from error
        if copied_report != release_report:
            raise DossierError("copied release verification is not authoritative")
        if hmac.compare_digest(
            release_report["public_key_spki_sha256"],
            decision["evidence_signer_spki_sha256"],
        ):
            raise DossierError("evidence and release roles must use different keys")
        pilot_report = _validate_pilot_signoff_trust(
            snapshots[SOURCE_PATHS["pilot_signoff_verification"]],
            pilot_policy_raw,
            expected_pilot_signoff_trust_policy_sha256,
            decision["release_revision"],
        )
        pilot_signoff_trust_policy_verified = True
        expected = _build_dossier(
            snapshots,
            decision,
            phase="final",
            generated_at_utc=decision["generated_at_utc"],
            status="pass",
            evidence_public_key_supplied=True,
            expected_evidence_key_id=expected_evidence_key_id,
            pilot_signoff_trust_policy_supplied=True,
            expected_pilot_signoff_trust_policy_sha256=(
                expected_pilot_signoff_trust_policy_sha256
            ),
            pilot_signoff_report=pilot_report,
            release_report=release_report,
            expected_release_key_id=expected_release_key_id,
        )
        _assert_expected_dossier(dossier, expected)
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": dossier["status"],
        "authorization": dossier["authorization"],
        "phase": phase,
        "candidate": decision["candidate"],
        "release_decision": decision["decision"],
        "release_revision": decision["release_revision"],
        "dossier_sha256": sha256(snapshots[INDEX_PATH]).hexdigest(),
        "semantic_authority": "ci.release_decision",
        "terminal_unsigned_index": True,
        "release_operator_attestation_verified": release_report is not None,
        "pilot_signoff_trust_policy_verified": (
            pilot_signoff_trust_policy_verified
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assemble, finalize, or verify an unsigned terminal release dossier."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    assemble = subparsers.add_parser("assemble", help="Create a preliminary dossier.")
    assemble.add_argument("--root", required=True)
    assemble.add_argument("--candidate-revision", required=True)
    assemble.add_argument("--runtime-version", required=True)
    assemble.add_argument("--evidence-public-key", default=None)
    assemble.add_argument("--expected-evidence-key-id", default=None)
    assemble.add_argument("--pilot-signoff-trust-policy", default=None)
    assemble.add_argument(
        "--expected-pilot-signoff-trust-policy-sha256", default=None
    )
    assemble.add_argument("--output", required=True)

    finalize = subparsers.add_parser("finalize", help="Create a verified final dossier.")
    finalize.add_argument("--root", required=True)
    finalize.add_argument("--release-attestation", default=None)
    finalize.add_argument("--evidence-public-key", default=None)
    finalize.add_argument("--expected-evidence-key-id", default=None)
    finalize.add_argument("--release-public-key", default=None)
    finalize.add_argument("--expected-release-key-id", default=None)
    finalize.add_argument("--pilot-signoff-trust-policy", default=None)
    finalize.add_argument(
        "--expected-pilot-signoff-trust-policy-sha256", default=None
    )
    finalize.add_argument("--output", required=True)

    verify = subparsers.add_parser("verify", help="Re-verify an exact dossier bundle.")
    verify.add_argument("--root", required=True)
    verify.add_argument("--evidence-public-key", default=None)
    verify.add_argument("--expected-evidence-key-id", default=None)
    verify.add_argument("--release-public-key", default=None)
    verify.add_argument("--expected-release-key-id", default=None)
    verify.add_argument("--pilot-signoff-trust-policy", default=None)
    verify.add_argument(
        "--expected-pilot-signoff-trust-policy-sha256", default=None
    )
    verify.add_argument("--output", default=None)
    verify.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def _optional_path(value: str | None) -> Path | None:
    return Path(value) if value is not None else None


def main() -> int:
    args = parse_args()
    try:
        if args.command == "assemble":
            dossier = assemble_dossier(
                Path(args.root),
                Path(args.output),
                args.candidate_revision,
                args.runtime_version,
                _optional_path(args.evidence_public_key),
                args.expected_evidence_key_id,
                _optional_path(args.pilot_signoff_trust_policy),
                args.expected_pilot_signoff_trust_policy_sha256,
            )
            print(
                f"preliminary release dossier written to {args.output} "
                f"(status={dossier['status']}, authorization=blocked)"
            )
            return 0
        if args.command == "finalize":
            dossier = finalize_dossier(
                Path(args.root),
                Path(args.output),
                _optional_path(args.release_attestation),
                _optional_path(args.evidence_public_key),
                args.expected_evidence_key_id,
                _optional_path(args.release_public_key),
                args.expected_release_key_id,
                _optional_path(args.pilot_signoff_trust_policy),
                args.expected_pilot_signoff_trust_policy_sha256,
            )
            print(
                f"final release dossier written to {args.output} "
                f"(status={dossier['status']}, authorization=go)"
            )
            return 0

        report = verify_dossier(
            Path(args.root),
            _optional_path(args.evidence_public_key),
            args.expected_evidence_key_id,
            _optional_path(args.release_public_key),
            args.expected_release_key_id,
            _optional_path(args.pilot_signoff_trust_policy),
            args.expected_pilot_signoff_trust_policy_sha256,
        )
        raw = _json_bytes(report)
        if args.output is not None:
            protected = [Path(args.root)]
            for value in (
                args.evidence_public_key,
                args.release_public_key,
                args.pilot_signoff_trust_policy,
            ):
                if value is not None:
                    protected.append(Path(value))
            _publish_report(Path(args.output), raw, protected)
            print(
                f"release dossier verification written to {args.output} "
                f"(status={report['status']})"
            )
        else:
            print(raw.decode("utf-8"), end="")
        return 0 if report["status"] == "pass" or not args.require_pass else 1
    except DossierBlocked as error:
        print(f"release dossier blocked: {error}", file=sys.stderr)
        return 1
    except (DossierError, release_decision.ReleaseDecisionError, OSError) as error:
        print(f"release dossier error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
