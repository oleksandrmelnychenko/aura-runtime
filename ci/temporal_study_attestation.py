#!/usr/bin/env python3

import argparse
import base64
import binascii
import hmac
import json
import math
import os
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

try:
    from ci import evidence_attestation as crypto_support
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import evidence_attestation as crypto_support


ATTESTATION_SCHEMA_VERSION = "aura.military.temporal_study_attestation.v1"
COMMITMENT_SCHEMA_VERSION = "aura.military.temporal_study_commitment.v1"
VERIFICATION_SCHEMA_VERSION = (
    "aura.military.temporal_study_attestation_verification.v1"
)
SIGNATURE_ALGORITHM = "Ed25519"
SIGNED_PAYLOAD_DOMAIN = b"aura.temporal-study.commitment-attestation.v1\x00"
MAX_COMMITMENT_BYTES = 1024 * 1024
MAX_ATTESTATION_BYTES = 64 * 1024
MAX_KEY_BYTES = 64 * 1024

COMMITMENT_FIELDS = (
    "schema_version",
    "study_id",
    "registered_at_ms",
    "corpus_class",
    "preregistration_canonical_sha256",
    "dataset_id",
    "corpus_sha256",
    "packet_id",
    "packet_canonical_sha256",
    "case_count",
    "minimum_reviewers_per_case",
    "minimum_acceptable_exact_set_pair_agreement_rate",
    "minimum_acceptable_krippendorff_alpha",
)
ATTESTATION_FIELDS = {
    "schema_version",
    "signature_algorithm",
    "key_id",
    "study_id",
    "registered_at_ms",
    "corpus_class",
    "commitment_file_sha256",
    "commitment_canonical_sha256",
    "preregistration_canonical_sha256",
    "corpus_sha256",
    "packet_canonical_sha256",
    "public_key_spki_sha256",
    "signature_base64",
}

AttestationError = crypto_support.AttestationError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sign or verify an AURA temporal study commitment with Ed25519."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign_parser = subparsers.add_parser("sign", help="Create a detached attestation.")
    sign_parser.add_argument("--commitment", required=True)
    sign_parser.add_argument("--private-key", required=True)
    sign_parser.add_argument("--key-id", required=True)
    sign_parser.add_argument("--output", required=True)

    verify_parser = subparsers.add_parser("verify", help="Verify a detached attestation.")
    verify_parser.add_argument("--commitment", required=True)
    verify_parser.add_argument("--attestation", required=True)
    verify_parser.add_argument("--public-key", required=True)
    verify_parser.add_argument("--expected-key-id", required=True)
    verify_parser.add_argument("--output", default=None)
    verify_parser.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def reject_duplicate_json_fields(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError(f"duplicate JSON field is not allowed: {key}")
        result[key] = value
    return result


def load_json(raw: bytes, label: str) -> dict:
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=reject_duplicate_json_fields
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AttestationError(f"{label} is invalid JSON: {error}") from error
    if not isinstance(payload, dict):
        raise AttestationError(f"{label} must be a JSON object")
    return payload


def lowercase_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def safe_token(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and 8 <= len(value) <= 64
        and all(character.isalnum() or character in "_.-" for character in value)
    )


def positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def validate_commitment(payload: dict) -> None:
    if set(payload) != set(COMMITMENT_FIELDS):
        raise AttestationError("temporal study commitment fields do not match the v1 schema")
    if payload.get("schema_version") != COMMITMENT_SCHEMA_VERSION:
        raise AttestationError("temporal study commitment schema_version is unsupported")
    if not safe_token(payload.get("study_id")) or not safe_token(payload.get("packet_id")):
        raise AttestationError("temporal study commitment identity is invalid")
    dataset_id = payload.get("dataset_id")
    if (
        not isinstance(dataset_id, str)
        or not dataset_id.strip()
        or len(dataset_id) > 128
        or any(character.isspace() and character not in " " for character in dataset_id)
    ):
        raise AttestationError("temporal study dataset_id is invalid")
    if payload.get("corpus_class") not in ("public_seed", "embargoed_external"):
        raise AttestationError("temporal study corpus_class is invalid")
    if not positive_integer(payload.get("registered_at_ms")):
        raise AttestationError("temporal study registered_at_ms is invalid")
    for field in (
        "preregistration_canonical_sha256",
        "corpus_sha256",
        "packet_canonical_sha256",
    ):
        if not lowercase_sha256(payload.get(field)):
            raise AttestationError(f"temporal study {field} is malformed")
    if not positive_integer(payload.get("case_count")):
        raise AttestationError("temporal study case_count is invalid")
    reviewer_count = payload.get("minimum_reviewers_per_case")
    if (
        not isinstance(reviewer_count, int)
        or isinstance(reviewer_count, bool)
        or not 2 <= reviewer_count <= 5
    ):
        raise AttestationError("temporal study reviewer minimum is invalid")
    for field in (
        "minimum_acceptable_exact_set_pair_agreement_rate",
        "minimum_acceptable_krippendorff_alpha",
    ):
        value = payload.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0.8 <= value <= 1.0
        ):
            raise AttestationError(f"temporal study {field} is invalid")


def canonical_commitment(payload: dict) -> bytes:
    validate_commitment(payload)
    ordered = {field: payload[field] for field in COMMITMENT_FIELDS}
    for field in (
        "minimum_acceptable_exact_set_pair_agreement_rate",
        "minimum_acceptable_krippendorff_alpha",
    ):
        ordered[field] = float(ordered[field])
    return json.dumps(
        ordered,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def commitment_claims(raw: bytes, payload: dict, public_key_der: bytes, key_id: str) -> dict:
    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "study_id": payload["study_id"],
        "registered_at_ms": payload["registered_at_ms"],
        "corpus_class": payload["corpus_class"],
        "commitment_file_sha256": sha256(raw).hexdigest(),
        "commitment_canonical_sha256": sha256(canonical_commitment(payload)).hexdigest(),
        "preregistration_canonical_sha256": payload[
            "preregistration_canonical_sha256"
        ],
        "corpus_sha256": payload["corpus_sha256"],
        "packet_canonical_sha256": payload["packet_canonical_sha256"],
        "public_key_spki_sha256": sha256(public_key_der).hexdigest(),
    }


def canonical_attestation_claims(attestation: dict) -> bytes:
    claims = {
        field: attestation[field]
        for field in sorted(ATTESTATION_FIELDS - {"signature_base64"})
    }
    return SIGNED_PAYLOAD_DOMAIN + json.dumps(
        claims,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def validate_private_key_file(path: Path) -> None:
    if path.is_symlink():
        raise AttestationError("Ed25519 private key must not be a symbolic link")
    crypto_support.read_bounded(path, MAX_KEY_BYTES, "Ed25519 private key")
    if os.name != "nt" and (path.stat().st_mode & 0o077) != 0:
        raise AttestationError(
            "Ed25519 private key permissions must not allow group or world access"
        )


def sign_commitment(commitment_path: Path, private_key_path: Path, key_id: str) -> dict:
    if not crypto_support.safe_key_id(key_id):
        raise AttestationError(
            "key_id must be 1..64 ASCII alphanumeric, '_', '-', or '.' characters"
        )
    raw = crypto_support.read_bounded(
        commitment_path, MAX_COMMITMENT_BYTES, "temporal study commitment"
    )
    payload = load_json(raw, "temporal study commitment")
    validate_private_key_file(private_key_path)
    public_key_der = crypto_support.public_key_der_from_private(private_key_path)
    attestation = commitment_claims(raw, payload, public_key_der, key_id)
    with tempfile.NamedTemporaryFile() as claims_file:
        claims_file.write(canonical_attestation_claims(attestation))
        claims_file.flush()
        signature = crypto_support.run_openssl(
            [
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                private_key_path.as_posix(),
                "-in",
                claims_file.name,
            ]
        )
    if len(signature) != 64:
        raise AttestationError("OpenSSL returned a malformed Ed25519 signature")
    attestation["signature_base64"] = base64.b64encode(signature).decode("ascii")
    return attestation


def load_attestation(path: Path) -> dict:
    raw = crypto_support.read_bounded(path, MAX_ATTESTATION_BYTES, "study attestation")
    payload = load_json(raw, "temporal study attestation")
    if set(payload) != ATTESTATION_FIELDS:
        raise AttestationError("temporal study attestation fields do not match the v1 schema")
    if payload.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
        raise AttestationError("temporal study attestation schema_version is unsupported")
    if payload.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        raise AttestationError("temporal study signature algorithm is unsupported")
    if not crypto_support.safe_key_id(payload.get("key_id", "")):
        raise AttestationError("temporal study attestation key_id is invalid")
    if not safe_token(payload.get("study_id")) or not positive_integer(
        payload.get("registered_at_ms")
    ):
        raise AttestationError("temporal study attestation identity is invalid")
    if payload.get("corpus_class") not in ("public_seed", "embargoed_external"):
        raise AttestationError("temporal study attestation corpus_class is invalid")
    for field in (
        "commitment_file_sha256",
        "commitment_canonical_sha256",
        "preregistration_canonical_sha256",
        "corpus_sha256",
        "packet_canonical_sha256",
        "public_key_spki_sha256",
    ):
        if not lowercase_sha256(payload.get(field)):
            raise AttestationError(f"temporal study attestation {field} is malformed")
    try:
        signature = base64.b64decode(payload["signature_base64"], validate=True)
    except (binascii.Error, ValueError) as error:
        raise AttestationError("temporal study signature is malformed") from error
    if len(signature) != 64:
        raise AttestationError("temporal study signature is malformed")
    return payload


def verify_commitment(
    commitment_path: Path,
    attestation_path: Path,
    public_key_path: Path,
    expected_key_id: str,
) -> dict:
    if not crypto_support.safe_key_id(expected_key_id):
        raise AttestationError("expected key_id is invalid")
    raw = crypto_support.read_bounded(
        commitment_path, MAX_COMMITMENT_BYTES, "temporal study commitment"
    )
    commitment = load_json(raw, "temporal study commitment")
    validate_commitment(commitment)
    crypto_support.read_bounded(public_key_path, MAX_KEY_BYTES, "Ed25519 public key")
    attestation = load_attestation(attestation_path)
    if not hmac.compare_digest(attestation["key_id"], expected_key_id):
        raise AttestationError("temporal study attestation key_id is not trusted")
    public_key_der = crypto_support.public_key_der_from_public(public_key_path)
    expected_claims = commitment_claims(
        raw, commitment, public_key_der, attestation["key_id"]
    )
    for field, expected in expected_claims.items():
        actual = attestation.get(field)
        if isinstance(expected, str) and isinstance(actual, str):
            matches = hmac.compare_digest(actual, expected)
        else:
            matches = actual == expected
        if not matches:
            raise AttestationError(
                f"temporal study commitment does not match attested field {field}"
            )

    signature = base64.b64decode(attestation["signature_base64"], validate=True)
    with (
        tempfile.NamedTemporaryFile() as signature_file,
        tempfile.NamedTemporaryFile() as claims_file,
    ):
        signature_file.write(signature)
        signature_file.flush()
        claims_file.write(canonical_attestation_claims(attestation))
        claims_file.flush()
        crypto_support.run_openssl(
            [
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                public_key_path.as_posix(),
                "-sigfile",
                signature_file.name,
                "-in",
                claims_file.name,
            ]
        )
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": "pass",
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": attestation["key_id"],
        "study_id": commitment["study_id"],
        "registered_at_ms": commitment["registered_at_ms"],
        "corpus_class": commitment["corpus_class"],
        "commitment_file_sha256": attestation["commitment_file_sha256"],
        "commitment_canonical_sha256": attestation[
            "commitment_canonical_sha256"
        ],
        "preregistration_canonical_sha256": commitment[
            "preregistration_canonical_sha256"
        ],
        "corpus_sha256": commitment["corpus_sha256"],
        "packet_canonical_sha256": commitment["packet_canonical_sha256"],
        "public_key_spki_sha256": attestation["public_key_spki_sha256"],
        "trusted_timestamp_assurance": "absent",
    }


def main() -> int:
    args = parse_args()
    try:
        if args.command == "sign":
            output = Path(args.output)
            crypto_support.ensure_distinct_output(
                output,
                [Path(args.commitment), Path(args.private_key)],
            )
            attestation = sign_commitment(
                Path(args.commitment), Path(args.private_key), args.key_id
            )
            crypto_support.write_json_atomic(output, attestation)
            print(f"temporal study attestation written to {output}")
            return 0

        report = verify_commitment(
            Path(args.commitment),
            Path(args.attestation),
            Path(args.public_key),
            args.expected_key_id,
        )
        if args.output:
            output = Path(args.output)
            crypto_support.ensure_distinct_output(
                output,
                [
                    Path(args.commitment),
                    Path(args.attestation),
                    Path(args.public_key),
                ],
            )
            crypto_support.write_json_atomic(output, report)
            print(
                "temporal study attestation verification written to "
                f"{output} (status=pass)"
            )
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except AttestationError as error:
        print(str(error), file=sys.stderr)
        return 1 if getattr(args, "require_pass", False) else 2


if __name__ == "__main__":
    sys.exit(main())
