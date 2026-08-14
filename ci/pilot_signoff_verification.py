#!/usr/bin/env python3
"""Verify four role-separated Ed25519 pilot review signoffs.

The trust policy is an external caller-pinned input.  Verification reports keep
the signed attestations needed for later re-verification, but never embed the
trusted public-key policy itself.
"""

import argparse
import base64
import binascii
import hmac
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

try:
    from ci import evidence_attestation as crypto_support
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import evidence_attestation as crypto_support


TRUST_POLICY_SCHEMA_VERSION = "aura.pilot_signoff_trust_policy.v1"
BUNDLE_SCHEMA_VERSION = "aura.pilot_review_signoff_bundle.v1"
ATTESTATION_SCHEMA_VERSION = "aura.pilot_review_signoff_attestation.v1"
CLAIM_SCHEMA_VERSION = "aura.pilot_review_signoff_claim.v1"
VERIFICATION_SCHEMA_VERSION = "aura.pilot_signoff_verification.v1"
SIGNOFFS_SCHEMA_VERSION = "aura.pilot_review_signoffs.v2"
SIGNATURE_ALGORITHM = "Ed25519"

TRUST_POLICY_DOMAIN = b"aura.pilot-signoff-trust-policy.v1\x00"
ATTESTATION_DOMAIN = b"aura.pilot-review-signoff-attestation.v1\x00"
SIGNOFF_SET_DOMAIN = b"aura.pilot-signoff-set.v1\x00"
SIGNER_SET_DOMAIN = b"aura.pilot-signoff-signer-set.v1\x00"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ED25519_FIELD = (1 << 255) - 19
ED25519_SUBGROUP_ORDER = (
    (1 << 252) + 27742317777372353535851937790883648493
)
ED25519_D = (-121665 * pow(121666, ED25519_FIELD - 2, ED25519_FIELD)) % ED25519_FIELD
ED25519_SQRT_M1 = pow(2, (ED25519_FIELD - 1) // 4, ED25519_FIELD)

MAX_TRUST_POLICY_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 256 * 1024
MAX_REPORT_BYTES = 256 * 1024
MAX_NOTES_BYTES = 4096
MAX_REVIEWER_BYTES = 256
MAX_POLICY_EPOCH = (1 << 63) - 1

REQUIRED_REVIEW_AREAS = (
    "false_positive_hotspots",
    "self_harm_boundary_cases",
    "trusted_adult_scenarios",
    "reputation_image_abuse",
)

POLICY_FIELDS = {"schema_version", "policy_id", "policy_epoch", "roles"}
POLICY_ROLE_FIELDS = {"area", "reviewer", "key_id", "public_key_hex"}
BUNDLE_FIELDS = {"schema_version", "release_revision", "attestations"}
ATTESTATION_FIELDS = {
    "schema_version",
    "signature_algorithm",
    "key_id",
    "public_key_spki_sha256",
    "claims",
    "signature_base64",
}
CLAIM_FIELDS = {
    "schema_version",
    "policy_id",
    "policy_epoch",
    "trust_policy_sha256",
    "area",
    "reviewer",
    "status",
    "reviewed_at_utc",
    "notes",
    "release_revision",
}
REPORT_FIELDS = {
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

LOWERCASE_SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_REVISION = re.compile(r"[0-9a-f]{40}")
UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class PilotSignoffError(Exception):
    """The pilot signoff evidence is malformed, untrusted, or inconsistent."""


def _canonical_json(payload: object) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise PilotSignoffError("pilot signoff payload is not finite JSON") from error


def _lowercase_sha256(value: object) -> bool:
    return isinstance(value, str) and LOWERCASE_SHA256.fullmatch(value) is not None


def _git_revision(value: object) -> bool:
    return isinstance(value, str) and GIT_REVISION.fullmatch(value) is not None


def _bounded_text(value: object, maximum: int, *, allow_empty: bool = False) -> bool:
    if not isinstance(value, str) or "\x00" in value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (allow_empty or bool(encoded)) and len(encoded) <= maximum


def _utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or UTC_TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value


def _ed25519_add(
    first: tuple[int, int, int, int],
    second: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """Add extended-coordinate Edwards25519 points without inversions."""

    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    field = ED25519_FIELD
    a = ((y1 - x1) * (y2 - x2)) % field
    b = ((y1 + x1) * (y2 + x2)) % field
    c = (2 * ED25519_D * t1 * t2) % field
    d = (2 * z1 * z2) % field
    e = (b - a) % field
    f = (d - c) % field
    g = (d + c) % field
    h = (b + a) % field
    return (
        (e * f) % field,
        (g * h) % field,
        (f * g) % field,
        (e * h) % field,
    )


def _ed25519_double(
    point: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """Double an extended-coordinate Edwards25519 point."""

    x, y, z, _t = point
    field = ED25519_FIELD
    a = (x * x) % field
    b = (y * y) % field
    c = (2 * z * z) % field
    d = (-a) % field
    e = ((x + y) * (x + y) - a - b) % field
    g = (d + b) % field
    f = (g - c) % field
    h = (d - b) % field
    return (
        (e * f) % field,
        (g * h) % field,
        (f * g) % field,
        (e * h) % field,
    )


def _ed25519_scalar_multiply(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, addend)
        addend = _ed25519_double(addend)
        scalar >>= 1
    return result


def _ed25519_is_identity(point: tuple[int, int, int, int]) -> bool:
    x, y, z, _t = point
    return x % ED25519_FIELD == 0 and (y - z) % ED25519_FIELD == 0


def _validate_prime_order_ed25519_encoding(encoded: bytes, label: str) -> None:
    """Reject non-canonical, torsion, and mixed-order Ed25519 points.

    OpenSSL accepts the encoded identity key and a universal forged signature
    for it.  A trusted role key and a signature's R component must therefore be
    canonical non-identity points in the prime-order subgroup, rather than only
    being 32 bytes accepted by the backend parser.
    """

    if len(encoded) != 32:
        raise PilotSignoffError(f"{label} is malformed")
    encoded_integer = int.from_bytes(encoded, "little")
    x_sign = encoded_integer >> 255
    y = encoded_integer & ((1 << 255) - 1)
    if y >= ED25519_FIELD:
        raise PilotSignoffError(f"{label} is non-canonical")
    y_squared = (y * y) % ED25519_FIELD
    denominator = (ED25519_D * y_squared + 1) % ED25519_FIELD
    if denominator == 0:
        raise PilotSignoffError(f"{label} is not an Edwards25519 point")
    x_squared = (
        (y_squared - 1)
        * pow(denominator, ED25519_FIELD - 2, ED25519_FIELD)
    ) % ED25519_FIELD
    x = pow(x_squared, (ED25519_FIELD + 3) // 8, ED25519_FIELD)
    if (x * x - x_squared) % ED25519_FIELD != 0:
        x = (x * ED25519_SQRT_M1) % ED25519_FIELD
    if (x * x - x_squared) % ED25519_FIELD != 0:
        raise PilotSignoffError(f"{label} is not an Edwards25519 point")
    if x == 0 and x_sign == 1:
        raise PilotSignoffError(f"{label} has a non-canonical x sign")
    if x & 1 != x_sign:
        x = ED25519_FIELD - x
    point = (x, y, 1, (x * y) % ED25519_FIELD)
    if _ed25519_is_identity(point) or not _ed25519_is_identity(
        _ed25519_scalar_multiply(point, ED25519_SUBGROUP_ORDER)
    ):
        raise PilotSignoffError(f"{label} is not a non-identity prime-order point")


def _public_key_der(public_key_hex: str) -> bytes:
    try:
        raw = bytes.fromhex(public_key_hex)
    except ValueError as error:
        raise PilotSignoffError("pilot signer public key is malformed") from error
    if len(raw) != 32:
        raise PilotSignoffError("pilot signer public key is malformed")
    _validate_prime_order_ed25519_encoding(raw, "pilot signer public key")
    return ED25519_SPKI_PREFIX + raw


def trust_policy_sha256(policy: dict) -> str:
    validate_trust_policy(policy)
    return sha256(TRUST_POLICY_DOMAIN + _canonical_json(policy)).hexdigest()


def validate_trust_policy(policy: object) -> None:
    if not isinstance(policy, dict) or set(policy) != POLICY_FIELDS:
        raise PilotSignoffError("pilot signoff trust-policy fields are invalid")
    if policy.get("schema_version") != TRUST_POLICY_SCHEMA_VERSION:
        raise PilotSignoffError("pilot signoff trust-policy schema is unsupported")
    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or not crypto_support.safe_key_id(policy_id):
        raise PilotSignoffError("pilot signoff trust-policy ID is invalid")
    epoch = policy.get("policy_epoch")
    if (
        not isinstance(epoch, int)
        or isinstance(epoch, bool)
        or not 1 <= epoch <= MAX_POLICY_EPOCH
    ):
        raise PilotSignoffError("pilot signoff trust-policy epoch is invalid")
    roles = policy.get("roles")
    if not isinstance(roles, list) or len(roles) != len(REQUIRED_REVIEW_AREAS):
        raise PilotSignoffError("pilot signoff trust-policy role set is invalid")

    key_ids: list[str] = []
    reviewers: list[str] = []
    public_keys: list[str] = []
    signer_spki: list[str] = []
    for expected_area, role in zip(REQUIRED_REVIEW_AREAS, roles, strict=True):
        if not isinstance(role, dict) or set(role) != POLICY_ROLE_FIELDS:
            raise PilotSignoffError("pilot signoff trust-policy role fields are invalid")
        reviewer = role.get("reviewer")
        key_id = role.get("key_id")
        public_key_hex = role.get("public_key_hex")
        if role.get("area") != expected_area:
            raise PilotSignoffError("pilot signoff trust-policy roles are not exact and ordered")
        if not _bounded_text(reviewer, MAX_REVIEWER_BYTES):
            raise PilotSignoffError("pilot signoff reviewer identity is invalid")
        if not isinstance(key_id, str) or not crypto_support.safe_key_id(key_id):
            raise PilotSignoffError("pilot signoff key ID is invalid")
        if (
            not isinstance(public_key_hex, str)
            or re.fullmatch(r"[0-9a-f]{64}", public_key_hex) is None
        ):
            raise PilotSignoffError("pilot signer public key is malformed")
        public_key_der = _public_key_der(public_key_hex)
        key_ids.append(key_id)
        reviewers.append(reviewer)
        public_keys.append(public_key_hex)
        signer_spki.append(sha256(public_key_der).hexdigest())
    if (
        len(set(key_ids)) != len(key_ids)
        or len(set(reviewers)) != len(reviewers)
        or len(set(public_keys)) != len(public_keys)
        or len(set(signer_spki)) != len(signer_spki)
    ):
        raise PilotSignoffError(
            "pilot review roles must use distinct reviewers, key IDs, and signing keys"
        )


def canonical_attestation_claims(attestation: dict) -> bytes:
    if not isinstance(attestation, dict) or set(attestation) != ATTESTATION_FIELDS:
        raise PilotSignoffError("pilot signoff attestation fields are invalid")
    signed = {
        field: attestation[field]
        for field in sorted(ATTESTATION_FIELDS - {"signature_base64"})
    }
    return ATTESTATION_DOMAIN + _canonical_json(signed)


def review_signoffs_projection(report: dict) -> dict:
    attestations = report.get("attestations") if isinstance(report, dict) else None
    if not isinstance(attestations, list):
        raise PilotSignoffError("pilot signoff verification attestations are invalid")
    signoffs = []
    for attestation in attestations:
        claims = attestation.get("claims") if isinstance(attestation, dict) else None
        if not isinstance(claims, dict):
            raise PilotSignoffError("pilot signoff claims are invalid")
        signoffs.append(
            {
                "area": claims.get("area"),
                "reviewer": claims.get("reviewer"),
                "status": claims.get("status"),
                "reviewed_at_utc": claims.get("reviewed_at_utc"),
                "notes": claims.get("notes"),
                "release_revision": claims.get("release_revision"),
            }
        )
    return {
        "schema_version": SIGNOFFS_SCHEMA_VERSION,
        "release_revision": report.get("release_revision"),
        "signoffs": signoffs,
    }


def signoff_set_sha256(projection: dict) -> str:
    return sha256(SIGNOFF_SET_DOMAIN + _canonical_json(projection)).hexdigest()


def signer_spki_set_sha256(signer_spki_sha256: list[str]) -> str:
    return sha256(
        SIGNER_SET_DOMAIN + _canonical_json(sorted(signer_spki_sha256))
    ).hexdigest()


def _verify_signature(attestation: dict, public_key_der: bytes) -> None:
    try:
        signature = base64.b64decode(
            attestation.get("signature_base64"), validate=True
        )
    except (binascii.Error, TypeError, ValueError) as error:
        raise PilotSignoffError("pilot signoff signature is malformed") from error
    if len(signature) != 64:
        raise PilotSignoffError("pilot signoff signature is malformed")
    if base64.b64encode(signature).decode("ascii") != attestation.get(
        "signature_base64"
    ):
        raise PilotSignoffError("pilot signoff signature is not canonical base64")
    _validate_prime_order_ed25519_encoding(
        signature[:32], "pilot signoff signature R"
    )
    if int.from_bytes(signature[32:], "little") >= ED25519_SUBGROUP_ORDER:
        raise PilotSignoffError("pilot signoff signature scalar is non-canonical")
    with (
        tempfile.NamedTemporaryFile() as public_key_file,
        tempfile.NamedTemporaryFile() as signature_file,
        tempfile.NamedTemporaryFile() as claims_file,
    ):
        public_key_file.write(public_key_der)
        public_key_file.flush()
        signature_file.write(signature)
        signature_file.flush()
        claims_file.write(canonical_attestation_claims(attestation))
        claims_file.flush()
        try:
            crypto_support.run_openssl(
                [
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    public_key_file.name,
                    "-sigfile",
                    signature_file.name,
                    "-in",
                    claims_file.name,
                ]
            )
        except crypto_support.AttestationError as error:
            raise PilotSignoffError("pilot signoff signature verification failed") from error


def _validate_attestations(
    attestations: object,
    policy: dict,
    policy_digest: str,
    release_revision: str,
) -> tuple[list[str], list[str]]:
    if not isinstance(attestations, list) or len(attestations) != len(
        REQUIRED_REVIEW_AREAS
    ):
        raise PilotSignoffError("pilot signoff attestation set is invalid")
    signer_spki: list[str] = []
    statuses: list[str] = []
    for expected_area, role, attestation in zip(
        REQUIRED_REVIEW_AREAS,
        policy["roles"],
        attestations,
        strict=True,
    ):
        if not isinstance(attestation, dict) or set(attestation) != ATTESTATION_FIELDS:
            raise PilotSignoffError("pilot signoff attestation fields are invalid")
        claims = attestation.get("claims")
        if not isinstance(claims, dict) or set(claims) != CLAIM_FIELDS:
            raise PilotSignoffError("pilot signoff claim fields are invalid")
        public_key_der = _public_key_der(role["public_key_hex"])
        expected_spki = sha256(public_key_der).hexdigest()
        if (
            attestation.get("schema_version") != ATTESTATION_SCHEMA_VERSION
            or attestation.get("signature_algorithm") != SIGNATURE_ALGORITHM
            or attestation.get("key_id") != role["key_id"]
            or attestation.get("public_key_spki_sha256") != expected_spki
            or claims.get("schema_version") != CLAIM_SCHEMA_VERSION
            or claims.get("policy_id") != policy["policy_id"]
            or not isinstance(claims.get("policy_epoch"), int)
            or isinstance(claims.get("policy_epoch"), bool)
            or claims.get("policy_epoch") != policy["policy_epoch"]
            or claims.get("trust_policy_sha256") != policy_digest
            or claims.get("area") != expected_area
            or claims.get("reviewer") != role["reviewer"]
            or claims.get("status") not in {"approved", "pending", "needs_changes"}
            or claims.get("release_revision") != release_revision
            or not _utc_timestamp(claims.get("reviewed_at_utc"))
            or (
                claims.get("notes") is not None
                and not _bounded_text(
                    claims.get("notes"), MAX_NOTES_BYTES, allow_empty=True
                )
            )
        ):
            raise PilotSignoffError(
                "pilot signoff claim does not match its trusted role or release"
            )
        _verify_signature(attestation, public_key_der)
        signer_spki.append(expected_spki)
        statuses.append(claims["status"])
    if len(set(signer_spki)) != len(signer_spki):
        raise PilotSignoffError("pilot signoff signer keys are not role-separated")
    return signer_spki, statuses


def _build_report(
    attestations: list[dict],
    policy: dict,
    policy_digest: str,
    release_revision: str,
) -> dict:
    signer_spki, statuses = _validate_attestations(
        attestations, policy, policy_digest, release_revision
    )
    provisional = {
        "release_revision": release_revision,
        "attestations": attestations,
    }
    projection = review_signoffs_projection(provisional)
    status = (
        "fail"
        if "needs_changes" in statuses
        else ("blocked" if "pending" in statuses else "pass")
    )
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": status,
        "release_revision": release_revision,
        "trust_policy_sha256": policy_digest,
        "policy_id": policy["policy_id"],
        "policy_epoch": policy["policy_epoch"],
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "required_review_areas": list(REQUIRED_REVIEW_AREAS),
        "verified_signoff_count": len(attestations),
        "distinct_signer_count": len(set(signer_spki)),
        "signoff_set_sha256": signoff_set_sha256(projection),
        "signer_spki_sha256": signer_spki,
        "signer_spki_set_sha256": signer_spki_set_sha256(signer_spki),
        "attestations": attestations,
    }


def verify_bundle(
    bundle: dict,
    trust_policy: dict,
    expected_trust_policy_sha256: str,
    expected_release_revision: str,
) -> dict:
    validate_trust_policy(trust_policy)
    if not _lowercase_sha256(expected_trust_policy_sha256):
        raise PilotSignoffError("expected pilot trust-policy digest is invalid")
    if not _git_revision(expected_release_revision):
        raise PilotSignoffError("expected pilot release revision is invalid")
    if not isinstance(bundle, dict) or set(bundle) != BUNDLE_FIELDS:
        raise PilotSignoffError("pilot signoff bundle fields are invalid")
    if (
        bundle.get("schema_version") != BUNDLE_SCHEMA_VERSION
        or bundle.get("release_revision") != expected_release_revision
    ):
        raise PilotSignoffError("pilot signoff bundle is stale or unsupported")
    policy_digest = trust_policy_sha256(trust_policy)
    if not hmac.compare_digest(policy_digest, expected_trust_policy_sha256):
        raise PilotSignoffError("pilot signoff trust policy is not caller-trusted")
    attestations = bundle.get("attestations")
    if not isinstance(attestations, list):
        raise PilotSignoffError("pilot signoff bundle attestations are invalid")
    return _build_report(
        attestations, trust_policy, policy_digest, expected_release_revision
    )


def validate_verification_report(
    report: dict,
    trust_policy: dict,
    expected_trust_policy_sha256: str,
    expected_release_revision: str,
) -> dict:
    validate_trust_policy(trust_policy)
    if not _lowercase_sha256(expected_trust_policy_sha256):
        raise PilotSignoffError("expected pilot trust-policy digest is invalid")
    if not _git_revision(expected_release_revision):
        raise PilotSignoffError("expected pilot release revision is invalid")
    if not isinstance(report, dict) or set(report) != REPORT_FIELDS:
        raise PilotSignoffError("pilot signoff verification fields are invalid")
    if (
        report.get("schema_version") != VERIFICATION_SCHEMA_VERSION
        or report.get("status") not in {"pass", "blocked", "fail"}
        or report.get("release_revision") != expected_release_revision
    ):
        raise PilotSignoffError("pilot signoff verification is stale or unsupported")
    policy_digest = trust_policy_sha256(trust_policy)
    if not hmac.compare_digest(policy_digest, expected_trust_policy_sha256):
        raise PilotSignoffError("pilot signoff trust policy is not caller-trusted")
    attestations = report.get("attestations")
    if not isinstance(attestations, list):
        raise PilotSignoffError("pilot signoff verification attestations are invalid")
    expected = _build_report(
        attestations, trust_policy, policy_digest, expected_release_revision
    )
    if _canonical_json(report) != _canonical_json(expected):
        raise PilotSignoffError("pilot signoff verification summary is inconsistent")
    return review_signoffs_projection(expected)


def _load_json(path: Path, maximum: int, label: str) -> dict:
    raw = crypto_support.read_bounded(path, maximum, label)
    try:
        payload = crypto_support.strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise PilotSignoffError(f"{label} is invalid JSON") from error
    if not isinstance(payload, dict):
        raise PilotSignoffError(f"{label} must be a JSON object")
    return payload


def _existing_file_identity(path: Path) -> tuple[int, int] | None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise PilotSignoffError("pilot signoff path identity is inaccessible") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PilotSignoffError("pilot signoff path must be a regular non-symlink file")
    return metadata.st_dev, metadata.st_ino


def _reject_existing_output_aliases(outputs: list[Path], inputs: list[Path]) -> None:
    input_identities = {_existing_file_identity(path) for path in inputs}
    input_identities.discard(None)
    output_identities: set[tuple[int, int]] = set()
    for output in outputs:
        identity = _existing_file_identity(output)
        if identity is None:
            continue
        if identity in input_identities or identity in output_identities:
            raise PilotSignoffError("pilot signoff output aliases another input or output")
        output_identities.add(identity)


def load_trust_policy(path: Path) -> dict:
    policy = _load_json(path, MAX_TRUST_POLICY_BYTES, "pilot signoff trust policy")
    validate_trust_policy(policy)
    return policy


def load_bundle(path: Path) -> dict:
    return _load_json(path, MAX_BUNDLE_BYTES, "pilot signoff bundle")


def load_verification_report(path: Path) -> dict:
    return _load_json(path, MAX_REPORT_BYTES, "pilot signoff verification")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify four external Ed25519 pilot review signoffs."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="Verify and freeze pilot signoffs.")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--trust-policy", required=True)
    verify.add_argument("--expected-trust-policy-sha256", required=True)
    verify.add_argument("--release-revision", required=True)
    verify.add_argument("--output", required=True)
    verify.add_argument("--signoffs-output", required=True)
    verify.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        bundle_path = Path(args.bundle)
        policy_path = Path(args.trust_policy)
        output = Path(args.output)
        signoffs_output = Path(args.signoffs_output)
        if output.resolve() == signoffs_output.resolve():
            raise PilotSignoffError("verification and signoff outputs must differ")
        protected = [bundle_path, policy_path]
        crypto_support.ensure_distinct_output(output, protected)
        crypto_support.ensure_distinct_output(signoffs_output, protected)
        _reject_existing_output_aliases(
            [output, signoffs_output],
            protected,
        )
        policy = load_trust_policy(policy_path)
        bundle = load_bundle(bundle_path)
        report = verify_bundle(
            bundle,
            policy,
            args.expected_trust_policy_sha256,
            args.release_revision,
        )
        projection = review_signoffs_projection(report)
        crypto_support.write_json_atomic(output, report)
        crypto_support.write_json_atomic(signoffs_output, projection)
        print(
            f"pilot signoff verification written to {output} "
            f"(status={report['status']})"
        )
        return 0 if report["status"] == "pass" or not args.require_pass else 1
    except (PilotSignoffError, crypto_support.AttestationError, OSError, ValueError) as error:
        print(f"pilot signoff verification error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
