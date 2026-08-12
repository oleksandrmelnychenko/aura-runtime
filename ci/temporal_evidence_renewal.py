#!/usr/bin/env python3

import argparse
import hmac
import json
import os
import stat
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

try:
    from ci import evidence_attestation as crypto_support
    from ci import temporal_study_attestation as study_support
    from ci import temporal_study_timestamp as timestamp_support
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import evidence_attestation as crypto_support
    import temporal_study_attestation as study_support
    import temporal_study_timestamp as timestamp_support


COMMITMENT_SCHEMA_VERSION = "aura.research.evidence_renewal_commitment.v1"
VERIFICATION_SCHEMA_VERSION = "aura.research.evidence_renewal_verification.v2"
INDEX_SCHEMA_VERSION = "aura.research.evidence_renewal_index.v1"
CHAIN_VERIFICATION_SCHEMA_VERSION = (
    "aura.research.evidence_renewal_chain_verification.v2"
)
RENEWAL_PROFILE = "aura_rfc3161_renewal_envelope_not_rfc4998_ers"
RENEWAL_ASSURANCE = "rfc3161_full_chain_crl_renewal"
CHAIN_ASSURANCE = "all_links_reverified_from_raw_rfc3161_evidence"
HASH_ALGORITHM = "sha256"
COMMITMENT_DOMAIN = b"aura.evidence-renewal.commitment.v1\x00"
EVIDENCE_SET_DOMAIN = b"aura.evidence-renewal.set.v1\x00"
PREVIOUS_LINK_DOMAIN = b"aura.evidence-renewal.previous-link.v1\x00"

MAX_COMMITMENT_BYTES = 4 * 1024 * 1024
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_ITEM_BYTES = 512 * 1024 * 1024
MAX_EVIDENCE_ITEM_COUNT = 256
MAX_TOTAL_EVIDENCE_BYTES = 4 * 1024 * 1024 * 1024
MAX_RENEWAL_LINKS = 32
MAX_DECLARED_CLOCK_SKEW_MS = 5 * 60 * 1000

EVIDENCE_ITEM_FIELDS = {"label", "size_bytes", "sha256"}
PREVIOUS_LINK_DESCRIPTOR_FIELDS = {
    "commitment_file_sha256",
    "commitment_canonical_sha256",
    "timestamp_request_sha256",
    "timestamp_response_sha256",
    "trust_anchor_bundle_sha256",
    "untrusted_chain_sha256",
    "revocation_crl_file_sha256s",
    "expected_policy_oid",
    "expected_tsa_spki_sha256",
    "evidence_set_sha256",
}
PREVIOUS_RENEWAL_FIELDS = PREVIOUS_LINK_DESCRIPTOR_FIELDS | {
    "link_evidence_sha256"
}
COMMITMENT_FIELDS = {
    "schema_version",
    "renewal_profile",
    "renewal_id",
    "sequence_number",
    "created_at_ms",
    "hash_algorithm",
    "evidence_item_count",
    "evidence_total_bytes",
    "evidence_set_sha256",
    "evidence_items",
    "previous_renewal",
}
INDEX_FIELDS = {"schema_version", "evidence_items", "renewals"}
INDEX_EVIDENCE_ITEM_FIELDS = {"label", "path"}
RENEWAL_PACKAGE_FIELDS = {
    "commitment",
    "timestamp_request",
    "timestamp_response",
    "ca_file",
    "untrusted_chain",
    "revocation_crls",
    "expected_policy_oid",
    "expected_tsa_spki_sha256",
}

RenewalError = crypto_support.AttestationError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create and verify AURA RFC 3161 evidence-renewal envelopes. "
            "This profile is deliberately not RFC 4998 ERS."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser(
        "create", help="Create a deterministic evidence-renewal commitment."
    )
    create_parser.add_argument("--renewal-id", required=True)
    create_parser.add_argument("--sequence-number", required=True, type=int)
    create_parser.add_argument("--created-at-ms", required=True, type=int)
    create_parser.add_argument("--evidence-item", action="append", required=True)
    create_parser.add_argument("--previous-link-package", default=None)
    create_parser.add_argument("--output", required=True)

    request_parser = subparsers.add_parser(
        "request", help="Create a nonce-bearing RFC 3161 request for a commitment."
    )
    request_parser.add_argument("--commitment", required=True)
    request_parser.add_argument("--policy-oid", required=True)
    request_parser.add_argument("--output", required=True)

    verify_parser = subparsers.add_parser(
        "verify", help="Verify one evidence-renewal link from raw inputs."
    )
    add_verification_arguments(verify_parser)
    verify_parser.add_argument("--output", default=None)
    verify_parser.add_argument("--require-pass", action="store_true")

    chain_parser = subparsers.add_parser(
        "verify-chain", help="Re-verify every renewal link from a path index."
    )
    chain_parser.add_argument("--index", required=True)
    chain_parser.add_argument("--output", default=None)
    chain_parser.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def add_verification_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--commitment", required=True)
    parser.add_argument("--evidence-item", action="append", required=True)
    parser.add_argument("--previous-link-package", default=None)
    parser.add_argument("--timestamp-request", required=True)
    parser.add_argument("--timestamp-response", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--untrusted-chain", default=None)
    parser.add_argument("--revocation-crl", action="append", required=True)
    parser.add_argument("--expected-policy-oid", required=True)
    parser.add_argument("--expected-tsa-spki-sha256", required=True)


def positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def safe_label(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "_.-" for character in value)
    )


def safe_renewal_id(value: object) -> bool:
    return safe_label(value) and len(value) >= 8


def canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def evidence_set_digest(items: list[dict]) -> str:
    return sha256(EVIDENCE_SET_DOMAIN + canonical_json(items)).hexdigest()


def parse_evidence_specifications(values: list[str]) -> list[tuple[str, Path]]:
    if not 1 <= len(values) <= MAX_EVIDENCE_ITEM_COUNT:
        raise RenewalError(
            f"evidence item count must be within 1..={MAX_EVIDENCE_ITEM_COUNT}"
        )
    parsed = []
    labels = set()
    paths = set()
    for value in values:
        if not isinstance(value, str) or "=" not in value:
            raise RenewalError("evidence item must use LABEL=PATH syntax")
        label, path_value = value.split("=", 1)
        if not safe_label(label) or not path_value:
            raise RenewalError("evidence item label or path is invalid")
        path = Path(path_value)
        resolved = path.resolve()
        if label in labels or resolved in paths:
            raise RenewalError("evidence item labels and paths must be unique")
        labels.add(label)
        paths.add(resolved)
        parsed.append((label, path))
    return parsed


def inspect_evidence_file(label: str, path: Path) -> dict:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RenewalError(f"evidence item {label} is inaccessible or a symlink") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RenewalError(f"evidence item {label} must be a regular file")
        if not 1 <= before.st_size <= MAX_EVIDENCE_ITEM_BYTES:
            raise RenewalError(
                f"evidence item {label} size must be within "
                f"1..={MAX_EVIDENCE_ITEM_BYTES} bytes"
            )
        digest = sha256()
        observed_size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            observed_size += len(chunk)
            if observed_size > MAX_EVIDENCE_ITEM_BYTES:
                raise RenewalError(f"evidence item {label} grew while being hashed")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if observed_size != before.st_size or identity_before != identity_after:
            raise RenewalError(f"evidence item {label} changed while being hashed")
        return {
            "label": label,
            "size_bytes": observed_size,
            "sha256": digest.hexdigest(),
        }
    finally:
        os.close(descriptor)


def inspect_evidence_set(specifications: list[tuple[str, Path]]) -> tuple[list[dict], int]:
    if not 1 <= len(specifications) <= MAX_EVIDENCE_ITEM_COUNT:
        raise RenewalError(
            f"evidence item count must be within 1..={MAX_EVIDENCE_ITEM_COUNT}"
        )
    labels = [label for label, _ in specifications]
    paths = [path.resolve() for _, path in specifications if isinstance(path, Path)]
    if (
        any(not safe_label(label) for label in labels)
        or len(paths) != len(specifications)
        or len(set(labels)) != len(labels)
        or len(set(paths)) != len(paths)
    ):
        raise RenewalError("evidence item labels and paths must be valid and unique")
    items = sorted(
        (inspect_evidence_file(label, path) for label, path in specifications),
        key=lambda item: item["label"],
    )
    total_bytes = sum(item["size_bytes"] for item in items)
    if total_bytes > MAX_TOTAL_EVIDENCE_BYTES:
        raise RenewalError("evidence set exceeds the total size limit")
    return items, total_bytes


def validate_evidence_items(items: object) -> tuple[list[dict], int]:
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_EVIDENCE_ITEM_COUNT:
        raise RenewalError("evidence renewal item list is invalid")
    labels = []
    total_bytes = 0
    for item in items:
        if not isinstance(item, dict) or set(item) != EVIDENCE_ITEM_FIELDS:
            raise RenewalError("evidence renewal item fields are invalid")
        label = item.get("label")
        size_bytes = item.get("size_bytes")
        digest = item.get("sha256")
        if (
            not safe_label(label)
            or not positive_integer(size_bytes)
            or size_bytes > MAX_EVIDENCE_ITEM_BYTES
            or not timestamp_support.lowercase_sha256(digest)
        ):
            raise RenewalError("evidence renewal item claims are invalid")
        labels.append(label)
        total_bytes += size_bytes
    if labels != sorted(set(labels)) or total_bytes > MAX_TOTAL_EVIDENCE_BYTES:
        raise RenewalError("evidence renewal items are not uniquely sorted or are too large")
    return items, total_bytes


def validate_commitment(payload: dict) -> None:
    if set(payload) != COMMITMENT_FIELDS:
        raise RenewalError("evidence renewal commitment fields do not match v1")
    if (
        payload.get("schema_version") != COMMITMENT_SCHEMA_VERSION
        or payload.get("renewal_profile") != RENEWAL_PROFILE
        or payload.get("hash_algorithm") != HASH_ALGORITHM
        or not safe_renewal_id(payload.get("renewal_id"))
        or not positive_integer(payload.get("sequence_number"))
        or payload["sequence_number"] > MAX_RENEWAL_LINKS
        or not positive_integer(payload.get("created_at_ms"))
    ):
        raise RenewalError("evidence renewal commitment identity is invalid")
    items, total_bytes = validate_evidence_items(payload.get("evidence_items"))
    if (
        isinstance(payload.get("evidence_item_count"), bool)
        or not isinstance(payload.get("evidence_item_count"), int)
        or payload.get("evidence_item_count") != len(items)
        or isinstance(payload.get("evidence_total_bytes"), bool)
        or not isinstance(payload.get("evidence_total_bytes"), int)
        or payload.get("evidence_total_bytes") != total_bytes
        or not timestamp_support.lowercase_sha256(payload.get("evidence_set_sha256"))
        or not hmac.compare_digest(
            payload["evidence_set_sha256"], evidence_set_digest(items)
        )
    ):
        raise RenewalError("evidence renewal set summary is inconsistent")
    previous = payload.get("previous_renewal")
    if payload["sequence_number"] == 1:
        if previous is not None:
            raise RenewalError("initial evidence renewal must not declare a predecessor")
        return
    if not isinstance(previous, dict) or set(previous) != PREVIOUS_RENEWAL_FIELDS:
        raise RenewalError("non-initial evidence renewal must declare its predecessor")
    required_digests = PREVIOUS_LINK_DESCRIPTOR_FIELDS - {
        "untrusted_chain_sha256",
        "revocation_crl_file_sha256s",
        "expected_policy_oid",
    }
    chain_digest = previous.get("untrusted_chain_sha256")
    crl_digests = previous.get("revocation_crl_file_sha256s")
    if (
        any(
            not timestamp_support.lowercase_sha256(previous.get(field))
            for field in required_digests
        )
        or not timestamp_support.lowercase_sha256(
            previous.get("link_evidence_sha256")
        )
        or (
            chain_digest is not None
            and not timestamp_support.lowercase_sha256(chain_digest)
        )
        or not isinstance(crl_digests, list)
        or not 1 <= len(crl_digests) <= timestamp_support.MAX_CRL_COUNT
        or crl_digests != sorted(set(crl_digests))
        or any(
            not timestamp_support.lowercase_sha256(digest) for digest in crl_digests
        )
        or not timestamp_support.safe_oid(previous.get("expected_policy_oid"))
    ):
        raise RenewalError("evidence renewal predecessor digests are malformed")
    if not hmac.compare_digest(
        previous["evidence_set_sha256"], payload["evidence_set_sha256"]
    ):
        raise RenewalError("timestamp renewal cannot silently replace the evidence set")
    descriptor = {
        field: previous[field] for field in PREVIOUS_LINK_DESCRIPTOR_FIELDS
    }
    if not hmac.compare_digest(
        previous["link_evidence_sha256"],
        sha256(PREVIOUS_LINK_DOMAIN + canonical_json(descriptor)).hexdigest(),
    ):
        raise RenewalError("evidence renewal predecessor package digest is inconsistent")


def canonical_commitment(payload: dict) -> bytes:
    validate_commitment(payload)
    return COMMITMENT_DOMAIN + canonical_json(payload)


def load_commitment(path: Path) -> tuple[bytes, dict]:
    raw = crypto_support.read_bounded(
        path, MAX_COMMITMENT_BYTES, "evidence renewal commitment"
    )
    payload = study_support.load_json(raw, "evidence renewal commitment")
    validate_commitment(payload)
    return raw, payload


def inspect_response_bytes(raw: bytes, label: str) -> dict:
    with tempfile.TemporaryDirectory() as temporary_directory:
        snapshot = Path(temporary_directory) / "timestamp-response.tsr"
        timestamp_support.write_bytes_atomic(snapshot, raw)
        response = timestamp_support.inspect_response(snapshot)
    accuracy_micros = response.get("accuracy_micros")
    submillisecond_micros = response.get("gen_time_submillisecond_micros")
    if (
        accuracy_micros is None
        or isinstance(accuracy_micros, bool)
        or not isinstance(accuracy_micros, int)
        or accuracy_micros <= 0
        or accuracy_micros > timestamp_support.MAX_TIMESTAMP_ACCURACY_MICROS
        or isinstance(submillisecond_micros, bool)
        or not isinstance(submillisecond_micros, int)
        or not 0 <= submillisecond_micros <= 999
    ):
        raise RenewalError(f"{label} must declare acceptable timestamp accuracy")
    return response


def previous_link_descriptor(package: dict) -> tuple[dict, dict, dict]:
    if set(package) != RENEWAL_PACKAGE_FIELDS:
        raise RenewalError("previous renewal link package fields are invalid")
    required_paths = (
        "commitment",
        "timestamp_request",
        "timestamp_response",
        "ca_file",
    )
    if any(not isinstance(package.get(field), Path) for field in required_paths):
        raise RenewalError("previous renewal link package paths are invalid")
    chain_path = package.get("untrusted_chain")
    if chain_path is not None and not isinstance(chain_path, Path):
        raise RenewalError("previous renewal untrusted chain path is invalid")
    crl_paths = package.get("revocation_crls")
    if (
        not isinstance(crl_paths, list)
        or not 1 <= len(crl_paths) <= timestamp_support.MAX_CRL_COUNT
        or any(not isinstance(path, Path) for path in crl_paths)
        or len(set(path.resolve() for path in crl_paths)) != len(crl_paths)
        or not timestamp_support.safe_oid(package.get("expected_policy_oid"))
        or not timestamp_support.lowercase_sha256(
            package.get("expected_tsa_spki_sha256")
        )
    ):
        raise RenewalError("previous renewal link trust claims are invalid")
    commitment_raw, commitment = load_commitment(package["commitment"])
    request_raw = crypto_support.read_bounded(
        package["timestamp_request"],
        timestamp_support.MAX_REQUEST_BYTES,
        "previous RFC 3161 timestamp request",
    )
    response_raw = crypto_support.read_bounded(
        package["timestamp_response"],
        timestamp_support.MAX_RESPONSE_BYTES,
        "previous RFC 3161 timestamp response",
    )
    response = inspect_response_bytes(response_raw, "previous RFC 3161 timestamp")
    ca_raw = crypto_support.read_bounded(
        package["ca_file"],
        timestamp_support.MAX_CA_BUNDLE_BYTES,
        "previous RFC 3161 trust-anchor bundle",
    )
    chain_raw = (
        crypto_support.read_bounded(
            chain_path,
            timestamp_support.MAX_UNTRUSTED_CHAIN_BYTES,
            "previous RFC 3161 untrusted chain",
        )
        if chain_path is not None
        else None
    )
    crl_raw = [
        crypto_support.read_bounded(
            path, timestamp_support.MAX_CRL_BYTES, "previous RFC 3161 CRL"
        )
        for path in crl_paths
    ]
    if sum(len(raw) for raw in crl_raw) > timestamp_support.MAX_TOTAL_CRL_BYTES:
        raise RenewalError("previous renewal CRL set is too large")
    crl_digests = sorted(sha256(raw).hexdigest() for raw in crl_raw)
    if len(set(crl_digests)) != len(crl_digests):
        raise RenewalError("previous renewal link repeats identical CRL evidence")
    descriptor = {
        "commitment_file_sha256": sha256(commitment_raw).hexdigest(),
        "commitment_canonical_sha256": sha256(
            canonical_commitment(commitment)
        ).hexdigest(),
        "timestamp_request_sha256": sha256(request_raw).hexdigest(),
        "timestamp_response_sha256": sha256(response_raw).hexdigest(),
        "trust_anchor_bundle_sha256": sha256(ca_raw).hexdigest(),
        "untrusted_chain_sha256": (
            sha256(chain_raw).hexdigest() if chain_raw is not None else None
        ),
        "revocation_crl_file_sha256s": crl_digests,
        "expected_policy_oid": package["expected_policy_oid"],
        "expected_tsa_spki_sha256": package["expected_tsa_spki_sha256"],
        "evidence_set_sha256": commitment["evidence_set_sha256"],
    }
    return descriptor, commitment, response


def predecessor_claims(
    renewal_id: str,
    sequence_number: int,
    evidence_set_sha256: str,
    previous_package: dict | None,
) -> dict | None:
    if sequence_number == 1:
        if previous_package is not None:
            raise RenewalError("initial renewal must not receive a predecessor package")
        return None
    if previous_package is None:
        raise RenewalError("non-initial renewal requires a predecessor link package")
    descriptor, previous, _ = previous_link_descriptor(previous_package)
    if (
        previous["renewal_id"] != renewal_id
        or previous["sequence_number"] != sequence_number - 1
    ):
        raise RenewalError("evidence renewal predecessor sequence is not contiguous")
    if not hmac.compare_digest(previous["evidence_set_sha256"], evidence_set_sha256):
        raise RenewalError("evidence set changed; start a new series or use full ERS renewal")
    return {
        **descriptor,
        "link_evidence_sha256": sha256(
            PREVIOUS_LINK_DOMAIN + canonical_json(descriptor)
        ).hexdigest(),
    }


def create_commitment(
    renewal_id: str,
    sequence_number: int,
    created_at_ms: int,
    evidence_specifications: list[tuple[str, Path]],
    previous_package: dict | None = None,
) -> dict:
    if (
        not safe_renewal_id(renewal_id)
        or not positive_integer(sequence_number)
        or sequence_number > MAX_RENEWAL_LINKS
        or not positive_integer(created_at_ms)
    ):
        raise RenewalError("evidence renewal creation arguments are invalid")
    items, total_bytes = inspect_evidence_set(evidence_specifications)
    set_digest = evidence_set_digest(items)
    payload = {
        "schema_version": COMMITMENT_SCHEMA_VERSION,
        "renewal_profile": RENEWAL_PROFILE,
        "renewal_id": renewal_id,
        "sequence_number": sequence_number,
        "created_at_ms": created_at_ms,
        "hash_algorithm": HASH_ALGORITHM,
        "evidence_item_count": len(items),
        "evidence_total_bytes": total_bytes,
        "evidence_set_sha256": set_digest,
        "evidence_items": items,
        "previous_renewal": predecessor_claims(
            renewal_id,
            sequence_number,
            set_digest,
            previous_package,
        ),
    }
    validate_commitment(payload)
    return payload


def verify_evidence_set(
    commitment: dict, evidence_specifications: list[tuple[str, Path]]
) -> None:
    observed, total_bytes = inspect_evidence_set(evidence_specifications)
    if observed != commitment["evidence_items"] or total_bytes != commitment[
        "evidence_total_bytes"
    ]:
        raise RenewalError("preserved evidence does not match the renewal commitment")


def inspect_previous_link(
    commitment: dict,
    previous_package: dict | None,
) -> dict:
    if commitment["sequence_number"] == 1:
        if previous_package is not None:
            raise RenewalError(
                "initial renewal verification received a predecessor package"
            )
        return {
            "previous_commitment_canonical_sha256": None,
            "previous_timestamp_response_sha256": None,
            "previous_link_evidence_sha256": None,
            "previous_latest_trusted_time_unix_ms": None,
        }
    if previous_package is None:
        raise RenewalError(
            "non-initial renewal verification requires a predecessor link package"
        )
    descriptor, previous, previous_response = previous_link_descriptor(
        previous_package
    )
    expected = commitment["previous_renewal"]
    observed = {
        **descriptor,
        "link_evidence_sha256": sha256(
            PREVIOUS_LINK_DOMAIN + canonical_json(descriptor)
        ).hexdigest(),
    }
    if expected != observed:
        raise RenewalError("evidence renewal predecessor package binding is invalid")
    if (
        previous["renewal_id"] != commitment["renewal_id"]
        or previous["sequence_number"] != commitment["sequence_number"] - 1
    ):
        raise RenewalError("evidence renewal predecessor sequence is not contiguous")
    accuracy_micros = previous_response["accuracy_micros"]
    submillisecond_micros = previous_response[
        "gen_time_submillisecond_micros"
    ]
    previous_exact_time_micros = (
        previous_response["gen_time_unix_ms"] * 1_000
        + submillisecond_micros
    )
    previous_latest = (
        previous_exact_time_micros + accuracy_micros + 999
    ) // 1_000
    return {
        "previous_commitment_canonical_sha256": descriptor[
            "commitment_canonical_sha256"
        ],
        "previous_timestamp_response_sha256": descriptor[
            "timestamp_response_sha256"
        ],
        "previous_link_evidence_sha256": observed["link_evidence_sha256"],
        "previous_latest_trusted_time_unix_ms": previous_latest,
    }


def verify_renewal(
    commitment_path: Path,
    evidence_specifications: list[tuple[str, Path]],
    request_path: Path,
    response_path: Path,
    ca_file_path: Path,
    untrusted_chain_path: Path | None,
    revocation_crl_paths: list[Path],
    expected_policy_oid: str,
    expected_tsa_spki_sha256: str,
    previous_package: dict | None = None,
) -> dict:
    commitment_raw, commitment = load_commitment(commitment_path)
    verify_evidence_set(commitment, evidence_specifications)
    predecessor = inspect_previous_link(commitment, previous_package)
    timestamp = timestamp_support.verify_document_timestamp(
        commitment_raw,
        request_path,
        response_path,
        ca_file_path,
        untrusted_chain_path,
        expected_policy_oid,
        expected_tsa_spki_sha256,
        revocation_crl_paths,
    )
    if (
        timestamp["gen_time_unix_ms"] + MAX_DECLARED_CLOCK_SKEW_MS
        < commitment["created_at_ms"]
    ):
        raise RenewalError("renewal timestamp predates declared commitment creation")
    previous_latest = predecessor["previous_latest_trusted_time_unix_ms"]
    if previous_latest is not None and previous_latest >= timestamp[
        "earliest_trusted_time_unix_ms"
    ]:
        raise RenewalError("renewal timestamp interval overlaps its predecessor")
    commitment_file_sha256 = timestamp.pop("timestamped_document_sha256")
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": "pass",
        "renewal_profile": RENEWAL_PROFILE,
        "renewal_assurance": RENEWAL_ASSURANCE,
        "rfc4998_ers_conformance": False,
        "all_preserved_evidence_bytes_rehashed": True,
        "predecessor_reverified_in_this_report": False,
        "renewal_id": commitment["renewal_id"],
        "sequence_number": commitment["sequence_number"],
        "created_at_ms": commitment["created_at_ms"],
        "evidence_item_count": commitment["evidence_item_count"],
        "evidence_total_bytes": commitment["evidence_total_bytes"],
        "evidence_set_sha256": commitment["evidence_set_sha256"],
        "commitment_file_sha256": commitment_file_sha256,
        "commitment_canonical_sha256": sha256(
            canonical_commitment(commitment)
        ).hexdigest(),
        **predecessor,
        "renewal_follows_previous_timestamp": previous_latest is not None,
        **timestamp,
    }


def resolve_path(base: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise RenewalError(f"renewal index {label} path is invalid")
    path = Path(value)
    return (base / path).resolve() if not path.is_absolute() else path.resolve()


def resolve_optional_path(base: Path, value: object, label: str) -> Path | None:
    if value is None:
        return None
    return resolve_path(base, value, label)


def resolve_link_package(package: object, base: Path, label: str) -> dict:
    if not isinstance(package, dict) or set(package) != RENEWAL_PACKAGE_FIELDS:
        raise RenewalError(f"{label} fields are invalid")
    result = dict(package)
    for field in (
        "commitment",
        "timestamp_request",
        "timestamp_response",
        "ca_file",
    ):
        result[field] = resolve_path(base, package.get(field), f"{label} {field}")
    result["untrusted_chain"] = resolve_optional_path(
        base, package.get("untrusted_chain"), f"{label} untrusted chain"
    )
    crls = package.get("revocation_crls")
    if (
        not isinstance(crls, list)
        or not 1 <= len(crls) <= timestamp_support.MAX_CRL_COUNT
    ):
        raise RenewalError(f"{label} CRL list is invalid")
    result["revocation_crls"] = [
        resolve_path(base, crl, f"{label} revocation CRL") for crl in crls
    ]
    if len(set(result["revocation_crls"])) != len(result["revocation_crls"]):
        raise RenewalError(f"{label} repeats a CRL path")
    if not timestamp_support.safe_oid(package.get("expected_policy_oid")):
        raise RenewalError(f"{label} policy OID is invalid")
    if not timestamp_support.lowercase_sha256(
        package.get("expected_tsa_spki_sha256")
    ):
        raise RenewalError(f"{label} TSA SPKI digest is invalid")
    return result


def load_link_package_file(path: Path) -> dict:
    raw = crypto_support.read_bounded(
        path, MAX_INDEX_BYTES, "evidence renewal link package"
    )
    payload = study_support.load_json(raw, "evidence renewal link package")
    return resolve_link_package(payload, path.parent.resolve(), "renewal link package")


def load_index(path: Path) -> tuple[bytes, list[tuple[str, Path]], list[dict]]:
    raw = crypto_support.read_bounded(path, MAX_INDEX_BYTES, "evidence renewal index")
    payload = study_support.load_json(raw, "evidence renewal index")
    if set(payload) != INDEX_FIELDS or payload.get("schema_version") != INDEX_SCHEMA_VERSION:
        raise RenewalError("evidence renewal index fields are invalid")
    base = path.parent.resolve()
    evidence_raw = payload.get("evidence_items")
    if (
        not isinstance(evidence_raw, list)
        or not 1 <= len(evidence_raw) <= MAX_EVIDENCE_ITEM_COUNT
    ):
        raise RenewalError("evidence renewal index item list is invalid")
    evidence_specifications = []
    for item in evidence_raw:
        if not isinstance(item, dict) or set(item) != INDEX_EVIDENCE_ITEM_FIELDS:
            raise RenewalError("evidence renewal index item fields are invalid")
        label = item.get("label")
        if not safe_label(label):
            raise RenewalError("evidence renewal index item label is invalid")
        evidence_specifications.append(
            (label, resolve_path(base, item.get("path"), "evidence item"))
        )
    parsed_specs = parse_evidence_specifications(
        [f"{label}={item_path}" for label, item_path in evidence_specifications]
    )
    renewals_raw = payload.get("renewals")
    if not isinstance(renewals_raw, list) or not 1 <= len(renewals_raw) <= MAX_RENEWAL_LINKS:
        raise RenewalError("evidence renewal index link count is invalid")
    packages = []
    for package in renewals_raw:
        packages.append(
            resolve_link_package(package, base, "evidence renewal index package")
        )
    return raw, parsed_specs, packages


def verify_chain(index_path: Path, output_path: Path | None = None) -> dict:
    index_raw, evidence_specifications, packages = load_index(index_path)
    if output_path is not None:
        protected = [index_path, *(path for _, path in evidence_specifications)]
        for package in packages:
            protected.extend(
                package[field]
                for field in (
                    "commitment",
                    "timestamp_request",
                    "timestamp_response",
                    "ca_file",
                    "untrusted_chain",
                )
                if package[field] is not None
            )
            protected.extend(package["revocation_crls"])
        crypto_support.ensure_distinct_output(output_path, protected)
    reports = []
    for index, package in enumerate(packages):
        previous = packages[index - 1] if index > 0 else None
        report = verify_renewal(
            package["commitment"],
            evidence_specifications,
            package["timestamp_request"],
            package["timestamp_response"],
            package["ca_file"],
            package["untrusted_chain"],
            package["revocation_crls"],
            package["expected_policy_oid"],
            package["expected_tsa_spki_sha256"],
            previous,
        )
        if report["sequence_number"] != index + 1:
            raise RenewalError("evidence renewal index sequence must start at one")
        if reports and (
            report["renewal_id"] != reports[0]["renewal_id"]
            or report["evidence_set_sha256"] != reports[0]["evidence_set_sha256"]
        ):
            raise RenewalError("evidence renewal chain identity changed")
        reports.append(report)
    revocation_digests = sorted(
        {
            digest
            for report in reports
            for digest in report["revocation_crl_der_sha256s"]
        }
    )
    return {
        "schema_version": CHAIN_VERIFICATION_SCHEMA_VERSION,
        "status": "pass",
        "renewal_profile": RENEWAL_PROFILE,
        "chain_assurance": CHAIN_ASSURANCE,
        "rfc4998_ers_conformance": False,
        "all_links_reverified_from_raw_inputs": True,
        "all_preserved_evidence_bytes_rehashed": True,
        "renewal_id": reports[0]["renewal_id"],
        "renewal_link_count": len(reports),
        "evidence_item_count": reports[0]["evidence_item_count"],
        "evidence_total_bytes": reports[0]["evidence_total_bytes"],
        "evidence_set_sha256": reports[0]["evidence_set_sha256"],
        "first_earliest_trusted_time_unix_ms": reports[0][
            "earliest_trusted_time_unix_ms"
        ],
        "last_latest_trusted_time_unix_ms": reports[-1][
            "latest_trusted_time_unix_ms"
        ],
        "revocation_assurance": timestamp_support.REVOCATION_ASSURANCE,
        "revocation_checked_timestamp_count": len(reports),
        "revocation_unique_crl_count": len(revocation_digests),
        "revocation_crl_evidence_set_sha256": sha256(
            "\n".join(revocation_digests).encode("ascii")
        ).hexdigest(),
        "renewal_commitment_canonical_sha256s": [
            report["commitment_canonical_sha256"] for report in reports
        ],
        "renewal_timestamp_response_sha256s": [
            report["response_sha256"] for report in reports
        ],
        "renewal_timestamp_request_sha256s": [
            report["request_sha256"] for report in reports
        ],
        "renewal_index_sha256": sha256(index_raw).hexdigest(),
        "privacy": {
            "evidence_paths_exported": False,
            "raw_evidence_exported": False,
            "raw_certificate_names_exported": False,
        },
    }


def verification_arguments_from_cli(args: argparse.Namespace) -> dict:
    return {
        "commitment_path": Path(args.commitment),
        "evidence_specifications": parse_evidence_specifications(args.evidence_item),
        "request_path": Path(args.timestamp_request),
        "response_path": Path(args.timestamp_response),
        "ca_file_path": Path(args.ca_file),
        "untrusted_chain_path": Path(args.untrusted_chain)
        if args.untrusted_chain
        else None,
        "revocation_crl_paths": [Path(path) for path in args.revocation_crl],
        "expected_policy_oid": args.expected_policy_oid,
        "expected_tsa_spki_sha256": args.expected_tsa_spki_sha256,
        "previous_package": load_link_package_file(Path(args.previous_link_package))
        if args.previous_link_package
        else None,
    }


def main() -> int:
    args = parse_args()
    try:
        if args.command == "create":
            evidence_specifications = parse_evidence_specifications(args.evidence_item)
            output = Path(args.output)
            protected = [path for _, path in evidence_specifications]
            previous_package = (
                load_link_package_file(Path(args.previous_link_package))
                if args.previous_link_package
                else None
            )
            if args.previous_link_package:
                protected.append(Path(args.previous_link_package))
            if previous_package is not None:
                protected.extend(
                    previous_package[field]
                    for field in (
                        "commitment",
                        "timestamp_request",
                        "timestamp_response",
                        "ca_file",
                        "untrusted_chain",
                    )
                    if previous_package[field] is not None
                )
                protected.extend(previous_package["revocation_crls"])
            crypto_support.ensure_distinct_output(output, protected)
            commitment = create_commitment(
                args.renewal_id,
                args.sequence_number,
                args.created_at_ms,
                evidence_specifications,
                previous_package,
            )
            crypto_support.write_json_atomic(output, commitment)
            print(f"evidence renewal commitment written to {output}")
            return 0

        if args.command == "request":
            commitment = Path(args.commitment)
            output = Path(args.output)
            commitment_raw, _ = load_commitment(commitment)
            crypto_support.ensure_distinct_output(output, [commitment])
            request = timestamp_support.create_request_for_document(
                commitment_raw,
                args.policy_oid,
            )
            timestamp_support.write_bytes_atomic(output, request)
            print(f"evidence renewal RFC 3161 request written to {output}")
            return 0

        if args.command == "verify":
            verification_arguments = verification_arguments_from_cli(args)
            if args.output:
                protected = [
                    verification_arguments["commitment_path"],
                    verification_arguments["request_path"],
                    verification_arguments["response_path"],
                    verification_arguments["ca_file_path"],
                    verification_arguments["untrusted_chain_path"],
                    *(path for _, path in verification_arguments["evidence_specifications"]),
                    *verification_arguments["revocation_crl_paths"],
                ]
                previous_package = verification_arguments["previous_package"]
                if args.previous_link_package:
                    protected.append(Path(args.previous_link_package))
                if previous_package is not None:
                    protected.extend(
                        previous_package[field]
                        for field in (
                            "commitment",
                            "timestamp_request",
                            "timestamp_response",
                            "ca_file",
                            "untrusted_chain",
                        )
                        if previous_package[field] is not None
                    )
                    protected.extend(previous_package["revocation_crls"])
                crypto_support.ensure_distinct_output(
                    Path(args.output), [path for path in protected if path is not None]
                )
            report = verify_renewal(**verification_arguments)
        else:
            output = Path(args.output) if args.output else None
            report = verify_chain(Path(args.index), output)

        if args.output:
            crypto_support.write_json_atomic(Path(args.output), report)
            print(f"evidence renewal verification written to {args.output} (status=pass)")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (RenewalError, UnicodeDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1 if getattr(args, "require_pass", False) else 2


if __name__ == "__main__":
    sys.exit(main())
