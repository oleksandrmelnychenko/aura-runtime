#!/usr/bin/env python3

import argparse
import base64
import binascii
import copy
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
    from ci import temporal_review_roster as roster_support
    from ci import temporal_study_attestation as study_support
    from ci import temporal_study_timestamp as timestamp_support
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import evidence_attestation as crypto_support
    import temporal_review_roster as roster_support
    import temporal_study_attestation as study_support
    import temporal_study_timestamp as timestamp_support


SUBMISSION_SCHEMA_VERSION = "aura.military.temporal_review_submission.v1"
ATTESTATION_SCHEMA_VERSION = (
    "aura.military.temporal_review_submission_attestation.v1"
)
VERIFICATION_SCHEMA_VERSION = (
    "aura.military.temporal_review_receipt_verification.v3"
)
INDEX_SCHEMA_VERSION = "aura.military.temporal_review_receipt_index.v3"
CHAIN_VERIFICATION_SCHEMA_VERSION = (
    "aura.military.temporal_review_receipt_chain_verification.v4"
)
REVIEW_BUNDLE_SCHEMA_VERSION = "aura.military.temporal_independent_review.v3"
STUDY_TIMESTAMP_SCHEMA_VERSION = (
    "aura.military.temporal_study_timestamp_verification.v3"
)
SIGNATURE_ALGORITHM = "Ed25519"
TIMESTAMP_ASSURANCE = "rfc3161_trusted_chain"
CHAIN_ASSURANCE = "individual_signed_rfc3161_receipts"
SIGNED_PAYLOAD_DOMAIN = b"aura.temporal-review.submission-attestation.v1\x00"

MAX_SUBMISSION_BYTES = 8 * 1024 * 1024
MAX_ATTESTATION_BYTES = 128 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_REVIEW_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_INDEX_BYTES = 1024 * 1024
MAX_TIMESTAMP_REPORT_BYTES = 1024 * 1024
MAX_CASES = 10_000
MAX_PARTICIPANTS = 32
MAX_REASON_CODES = 64

SUBMISSION_FIELDS = {
    "schema_version",
    "study_id",
    "preregistration_canonical_sha256",
    "study_commitment_canonical_sha256",
    "packet_id",
    "packet_canonical_sha256",
    "participant_token",
    "affiliation_token",
    "role",
    "decisions",
    "reviewer_receipt_links",
}
DECISION_FIELDS = {
    "blind_case_token",
    "expected_reason_codes",
    "completed_at_ms",
}
RECEIPT_LINK_FIELDS = {
    "participant_token",
    "submission_attestation_sha256",
    "timestamp_response_sha256",
}
ATTESTATION_FIELDS = {
    "schema_version",
    "signature_algorithm",
    "key_id",
    "study_id",
    "packet_id",
    "participant_token",
    "role",
    "submission_file_sha256",
    "submission_canonical_sha256",
    "public_key_spki_sha256",
    "signature_base64",
}
PACKAGE_FIELDS = {
    "submission",
    "attestation",
    "public_key",
    "expected_key_id",
    "expected_signer_spki_sha256",
    "timestamp_request",
    "timestamp_response",
    "ca_file",
    "untrusted_chain",
    "revocation_crls",
    "expected_policy_oid",
    "expected_tsa_spki_sha256",
}
INDEX_FIELDS = {
    "schema_version",
    "review_bundle",
    "study_timestamp_receipt",
    "review_roster_receipt",
    "reviewer_receipts",
    "adjudicator_receipt",
}
ROSTER_PACKAGE_FIELDS = {
    "roster",
    "attestation",
    "public_key",
    "expected_key_id",
    "expected_signer_spki_sha256",
    "timestamp_request",
    "timestamp_response",
    "ca_file",
    "untrusted_chain",
    "revocation_crls",
    "expected_policy_oid",
    "expected_tsa_spki_sha256",
}
STUDY_TIMESTAMP_PACKAGE_FIELDS = {
    "commitment",
    "timestamp_request",
    "timestamp_response",
    "ca_file",
    "untrusted_chain",
    "revocation_crls",
    "expected_policy_oid",
    "expected_tsa_spki_sha256",
}
REVIEW_BUNDLE_FIELDS = {
    "schema_version",
    "study_id",
    "preregistration_canonical_sha256",
    "review_bundle_id",
    "packet_id",
    "packet_canonical_sha256",
    "protocol",
    "reviewers",
    "cases",
}
PROTOCOL_FIELDS = {
    "label_blinding",
    "minimum_reviewers_per_case",
    "distinct_reviewer_affiliations",
    "independent_adjudicator",
}

ReceiptError = crypto_support.AttestationError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Sign, timestamp, assemble, and verify independently witnessed AURA "
            "temporal-review submissions."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign_parser = subparsers.add_parser("sign", help="Sign one frozen submission.")
    sign_parser.add_argument("--submission", required=True)
    sign_parser.add_argument("--private-key", required=True)
    sign_parser.add_argument("--key-id", required=True)
    sign_parser.add_argument("--output", required=True)

    request_parser = subparsers.add_parser(
        "request", help="Create an RFC 3161 request for a signed attestation."
    )
    request_parser.add_argument("--attestation", required=True)
    request_parser.add_argument("--policy-oid", required=True)
    request_parser.add_argument("--output", required=True)

    verify_parser = subparsers.add_parser(
        "verify", help="Verify one signature and its RFC 3161 receipt."
    )
    add_receipt_arguments(verify_parser)
    verify_parser.add_argument("--output", default=None)
    verify_parser.add_argument("--require-pass", action="store_true")

    assemble_parser = subparsers.add_parser(
        "assemble", help="Deterministically assemble a v3 review bundle."
    )
    assemble_parser.add_argument("--template", required=True)
    assemble_parser.add_argument("--study-commitment", required=True)
    assemble_parser.add_argument(
        "--reviewer-submission", action="append", required=True
    )
    assemble_parser.add_argument("--adjudicator-submission", required=True)
    assemble_parser.add_argument("--output", required=True)

    chain_parser = subparsers.add_parser(
        "verify-chain", help="Verify every receipt and the complete time chain."
    )
    chain_parser.add_argument("--index", required=True)
    chain_parser.add_argument("--output", default=None)
    chain_parser.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def add_receipt_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--submission", required=True)
    parser.add_argument("--attestation", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--expected-key-id", required=True)
    parser.add_argument("--expected-signer-spki-sha256", required=True)
    parser.add_argument("--timestamp-request", required=True)
    parser.add_argument("--timestamp-response", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--untrusted-chain", default=None)
    parser.add_argument("--revocation-crl", action="append", required=True)
    parser.add_argument("--expected-policy-oid", required=True)
    parser.add_argument("--expected-tsa-spki-sha256", required=True)


def positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def safe_token(value: object, *, maximum: int = 64) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and 8 <= len(value) <= maximum
        and all(character.isalnum() or character in "_.-" for character in value)
    )


def reason_code(value: object) -> bool:
    return safe_token(value, maximum=128)


def read_json(path: Path, maximum: int, label: str) -> tuple[bytes, dict]:
    raw = crypto_support.read_bounded(path, maximum, label)
    return raw, study_support.load_json(raw, label)


def validate_submission(payload: dict) -> None:
    if set(payload) != SUBMISSION_FIELDS:
        raise ReceiptError("temporal review submission fields do not match the v1 schema")
    if payload.get("schema_version") != SUBMISSION_SCHEMA_VERSION:
        raise ReceiptError("temporal review submission schema_version is unsupported")
    for field in ("study_id", "packet_id", "participant_token", "affiliation_token"):
        if not safe_token(payload.get(field)):
            raise ReceiptError(f"temporal review submission {field} is invalid")
    for field in (
        "preregistration_canonical_sha256",
        "study_commitment_canonical_sha256",
        "packet_canonical_sha256",
    ):
        if not timestamp_support.lowercase_sha256(payload.get(field)):
            raise ReceiptError(f"temporal review submission {field} is malformed")
    role = payload.get("role")
    if role not in ("reviewer", "adjudicator"):
        raise ReceiptError("temporal review submission role is invalid")

    decisions = payload.get("decisions")
    if not isinstance(decisions, list) or not 1 <= len(decisions) <= MAX_CASES:
        raise ReceiptError("temporal review submission decision count is invalid")
    observed_case_tokens = []
    for decision in decisions:
        if not isinstance(decision, dict) or set(decision) != DECISION_FIELDS:
            raise ReceiptError("temporal review decision fields are invalid")
        blind_case_token = decision.get("blind_case_token")
        if not safe_token(blind_case_token, maximum=96):
            raise ReceiptError("temporal review decision blind token is invalid")
        labels = decision.get("expected_reason_codes")
        if (
            not isinstance(labels, list)
            or len(labels) > MAX_REASON_CODES
            or any(not reason_code(label) for label in labels)
            or labels != sorted(set(labels))
        ):
            raise ReceiptError("temporal review decision reason codes are invalid")
        if not positive_integer(decision.get("completed_at_ms")):
            raise ReceiptError("temporal review decision completion time is invalid")
        observed_case_tokens.append(blind_case_token)
    if observed_case_tokens != sorted(set(observed_case_tokens)):
        raise ReceiptError("temporal review decisions must have unique sorted case tokens")

    links = payload.get("reviewer_receipt_links")
    if not isinstance(links, list) or len(links) > MAX_PARTICIPANTS:
        raise ReceiptError("temporal review receipt links are invalid")
    if role == "reviewer" and links:
        raise ReceiptError("reviewer submissions must not contain reviewer receipt links")
    if role == "adjudicator" and len(links) < 2:
        raise ReceiptError("adjudicator submission must bind at least two reviewer receipts")
    observed_participants = []
    for link in links:
        if not isinstance(link, dict) or set(link) != RECEIPT_LINK_FIELDS:
            raise ReceiptError("reviewer receipt link fields are invalid")
        participant_token = link.get("participant_token")
        if not safe_token(participant_token):
            raise ReceiptError("reviewer receipt link participant is invalid")
        for field in (
            "submission_attestation_sha256",
            "timestamp_response_sha256",
        ):
            if not timestamp_support.lowercase_sha256(link.get(field)):
                raise ReceiptError(f"reviewer receipt link {field} is malformed")
        observed_participants.append(participant_token)
    if observed_participants != sorted(set(observed_participants)):
        raise ReceiptError("reviewer receipt links must have unique sorted participants")


def canonical_submission(payload: dict) -> bytes:
    validate_submission(payload)
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def submission_claims(
    raw: bytes,
    submission: dict,
    public_key_der: bytes,
    key_id: str,
) -> dict:
    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "study_id": submission["study_id"],
        "packet_id": submission["packet_id"],
        "participant_token": submission["participant_token"],
        "role": submission["role"],
        "submission_file_sha256": sha256(raw).hexdigest(),
        "submission_canonical_sha256": sha256(
            canonical_submission(submission)
        ).hexdigest(),
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


def read_private_key(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReceiptError(
            "review private key is missing, inaccessible, or a symbolic link"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReceiptError("review private key must be a regular file")
        if not 1 <= metadata.st_size <= MAX_KEY_BYTES:
            raise ReceiptError(
                f"review private key size must be within 1..={MAX_KEY_BYTES} bytes"
            )
        if os.name != "nt" and (metadata.st_mode & 0o077) != 0:
            raise ReceiptError(
                "review private key permissions must not allow group or world access"
            )
        raw = bytearray()
        while len(raw) <= MAX_KEY_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_KEY_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if not 1 <= len(raw) <= MAX_KEY_BYTES:
            raise ReceiptError(
                f"review private key size must be within 1..={MAX_KEY_BYTES} bytes"
            )
        return bytes(raw)
    finally:
        os.close(descriptor)


def sign_submission(
    submission_path: Path,
    private_key_path: Path,
    key_id: str,
) -> dict:
    if not crypto_support.safe_key_id(key_id):
        raise ReceiptError("review key_id is invalid")
    raw, submission = read_json(
        submission_path, MAX_SUBMISSION_BYTES, "temporal review submission"
    )
    validate_submission(submission)
    private_key = read_private_key(private_key_path)
    with tempfile.TemporaryDirectory() as temporary_directory:
        key_snapshot = Path(temporary_directory) / "review-private-key.pem"
        timestamp_support.write_bytes_atomic(key_snapshot, private_key)
        if os.name != "nt":
            key_snapshot.chmod(0o600)
        public_key_der = crypto_support.public_key_der_from_private(key_snapshot)
        attestation = submission_claims(raw, submission, public_key_der, key_id)
        with tempfile.NamedTemporaryFile() as claims_file:
            claims_file.write(canonical_attestation_claims(attestation))
            claims_file.flush()
            signature = crypto_support.run_openssl(
                [
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    key_snapshot.as_posix(),
                    "-in",
                    claims_file.name,
                ]
            )
    if len(signature) != 64:
        raise ReceiptError("OpenSSL returned a malformed Ed25519 review signature")
    attestation["signature_base64"] = base64.b64encode(signature).decode("ascii")
    return attestation


def load_attestation(path: Path) -> tuple[bytes, dict]:
    raw, payload = read_json(
        path, MAX_ATTESTATION_BYTES, "temporal review submission attestation"
    )
    if set(payload) != ATTESTATION_FIELDS:
        raise ReceiptError("review attestation fields do not match the v1 schema")
    if payload.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
        raise ReceiptError("review attestation schema_version is unsupported")
    if payload.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        raise ReceiptError("review attestation signature algorithm is unsupported")
    if not crypto_support.safe_key_id(payload.get("key_id", "")):
        raise ReceiptError("review attestation key_id is invalid")
    for field in ("study_id", "packet_id", "participant_token"):
        if not safe_token(payload.get(field)):
            raise ReceiptError(f"review attestation {field} is invalid")
    if payload.get("role") not in ("reviewer", "adjudicator"):
        raise ReceiptError("review attestation role is invalid")
    for field in (
        "submission_file_sha256",
        "submission_canonical_sha256",
        "public_key_spki_sha256",
    ):
        if not timestamp_support.lowercase_sha256(payload.get(field)):
            raise ReceiptError(f"review attestation {field} is malformed")
    try:
        signature = base64.b64decode(payload.get("signature_base64", ""), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ReceiptError("review attestation signature is malformed") from error
    if len(signature) != 64:
        raise ReceiptError("review attestation signature is malformed")
    return raw, payload


def verify_submission_signature(
    submission_path: Path,
    attestation_path: Path,
    public_key_path: Path,
    expected_key_id: str,
) -> tuple[bytes, dict, bytes, dict, str]:
    if not crypto_support.safe_key_id(expected_key_id):
        raise ReceiptError("expected review key_id is invalid")
    submission_raw, submission = read_json(
        submission_path, MAX_SUBMISSION_BYTES, "temporal review submission"
    )
    validate_submission(submission)
    attestation_raw, attestation = load_attestation(attestation_path)
    public_key_raw = crypto_support.read_bounded(
        public_key_path, MAX_KEY_BYTES, "review public key"
    )
    with tempfile.TemporaryDirectory() as temporary_directory:
        public_key_snapshot = Path(temporary_directory) / "review-public-key.pem"
        timestamp_support.write_bytes_atomic(public_key_snapshot, public_key_raw)
        public_key_der = crypto_support.public_key_der_from_public(public_key_snapshot)
        expected_claims = submission_claims(
            submission_raw, submission, public_key_der, expected_key_id
        )
        if not hmac.compare_digest(attestation["key_id"], expected_key_id):
            raise ReceiptError("review attestation key_id is not trusted")
        for field, expected in expected_claims.items():
            actual = attestation.get(field)
            matches = (
                hmac.compare_digest(actual, expected)
                if isinstance(actual, str) and isinstance(expected, str)
                else actual == expected
            )
            if not matches:
                raise ReceiptError(
                    f"review submission does not match attested field {field}"
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
                    public_key_snapshot.as_posix(),
                    "-sigfile",
                    signature_file.name,
                    "-in",
                    claims_file.name,
                ]
            )
    return (
        submission_raw,
        submission,
        attestation_raw,
        attestation,
        sha256(public_key_der).hexdigest(),
    )


def verify_receipt(
    submission_path: Path,
    attestation_path: Path,
    public_key_path: Path,
    expected_key_id: str,
    expected_signer_spki_sha256: str,
    timestamp_request_path: Path,
    timestamp_response_path: Path,
    ca_file_path: Path,
    untrusted_chain_path: Path | None,
    expected_policy_oid: str,
    expected_tsa_spki_sha256: str,
    revocation_crl_paths: list[Path],
) -> dict:
    if not timestamp_support.lowercase_sha256(expected_signer_spki_sha256):
        raise ReceiptError("expected review signer SPKI digest is malformed")
    (
        submission_raw,
        submission,
        attestation_raw,
        attestation,
        public_key_spki_sha256,
    ) = verify_submission_signature(
        submission_path,
        attestation_path,
        public_key_path,
        expected_key_id,
    )
    if not hmac.compare_digest(
        public_key_spki_sha256, expected_signer_spki_sha256
    ):
        raise ReceiptError("review signer does not match the expected SPKI digest")
    timestamp = timestamp_support.verify_document_timestamp(
        attestation_raw,
        timestamp_request_path,
        timestamp_response_path,
        ca_file_path,
        untrusted_chain_path,
        expected_policy_oid,
        expected_tsa_spki_sha256,
        revocation_crl_paths,
    )
    attestation_file_sha256 = timestamp.pop("timestamped_document_sha256")
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": "pass",
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": expected_key_id,
        "study_id": submission["study_id"],
        "preregistration_canonical_sha256": submission[
            "preregistration_canonical_sha256"
        ],
        "study_commitment_canonical_sha256": submission[
            "study_commitment_canonical_sha256"
        ],
        "packet_id": submission["packet_id"],
        "packet_canonical_sha256": submission["packet_canonical_sha256"],
        "participant_token": submission["participant_token"],
        "affiliation_token": submission["affiliation_token"],
        "role": submission["role"],
        "decision_count": len(submission["decisions"]),
        "reviewer_receipt_link_count": len(submission["reviewer_receipt_links"]),
        "submission_file_sha256": sha256(submission_raw).hexdigest(),
        "submission_canonical_sha256": sha256(
            canonical_submission(submission)
        ).hexdigest(),
        "submission_attestation_sha256": attestation_file_sha256,
        "public_key_spki_sha256": public_key_spki_sha256,
        **timestamp,
    }


def validate_template(payload: dict) -> None:
    if set(payload) != REVIEW_BUNDLE_FIELDS:
        raise ReceiptError("temporal review template fields are invalid")
    if payload.get("schema_version") != REVIEW_BUNDLE_SCHEMA_VERSION:
        raise ReceiptError("temporal review template schema_version is unsupported")
    for field in ("study_id", "review_bundle_id", "packet_id"):
        if not safe_token(payload.get(field)):
            raise ReceiptError(f"temporal review template {field} is invalid")
    for field in (
        "preregistration_canonical_sha256",
        "packet_canonical_sha256",
    ):
        if not timestamp_support.lowercase_sha256(payload.get(field)):
            raise ReceiptError(f"temporal review template {field} is malformed")
    protocol = payload.get("protocol")
    if not isinstance(protocol, dict) or set(protocol) != PROTOCOL_FIELDS:
        raise ReceiptError("temporal review protocol fields are invalid")
    minimum_reviewers = protocol.get("minimum_reviewers_per_case")
    if (
        protocol.get("label_blinding") is not True
        or protocol.get("distinct_reviewer_affiliations") is not True
        or protocol.get("independent_adjudicator") is not True
        or isinstance(minimum_reviewers, bool)
        or not isinstance(minimum_reviewers, int)
        or not 2 <= minimum_reviewers <= 5
    ):
        raise ReceiptError("temporal review protocol is not high assurance")
    if payload.get("reviewers") != []:
        raise ReceiptError("temporal review assembly template must have no reviewers")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ReceiptError("temporal review template case count is invalid")
    observed = set()
    for case in cases:
        blind_case_token = case.get("blind_case_token") if isinstance(case, dict) else None
        if (
            not isinstance(case, dict)
            or set(case) != {"blind_case_token", "annotations", "adjudication"}
            or not safe_token(blind_case_token, maximum=96)
            or case.get("annotations") != []
            or case.get("adjudication") is not None
            or blind_case_token in observed
        ):
            raise ReceiptError("temporal review template case is invalid")
        observed.add(blind_case_token)


def validate_submission_binding(
    submission: dict,
    template: dict,
    commitment_canonical_sha256: str,
) -> None:
    bindings = (
        ("study_id", "study_id"),
        ("preregistration_canonical_sha256", "preregistration_canonical_sha256"),
        ("packet_id", "packet_id"),
        ("packet_canonical_sha256", "packet_canonical_sha256"),
    )
    if any(
        submission[submission_field] != template[template_field]
        for submission_field, template_field in bindings
    ) or submission["study_commitment_canonical_sha256"] != commitment_canonical_sha256:
        raise ReceiptError("temporal review submission is not bound to the study packet")


def assemble_bundle(
    template: dict,
    commitment_canonical_sha256: str,
    reviewer_submissions: list[dict],
    adjudicator_submission: dict,
) -> dict:
    validate_template(template)
    if not timestamp_support.lowercase_sha256(commitment_canonical_sha256):
        raise ReceiptError("study commitment canonical digest is malformed")
    if not 2 <= len(reviewer_submissions) <= MAX_PARTICIPANTS:
        raise ReceiptError("review bundle requires at least two reviewer submissions")
    participant_tokens = set()
    affiliation_tokens = set()
    for submission in [*reviewer_submissions, adjudicator_submission]:
        validate_submission(submission)
        validate_submission_binding(submission, template, commitment_canonical_sha256)
        if submission["participant_token"] in participant_tokens:
            raise ReceiptError("review participants must be unique")
        if submission["affiliation_token"] in affiliation_tokens:
            raise ReceiptError("review participant affiliations must be distinct")
        participant_tokens.add(submission["participant_token"])
        affiliation_tokens.add(submission["affiliation_token"])
    if any(submission["role"] != "reviewer" for submission in reviewer_submissions):
        raise ReceiptError("reviewer submission has the wrong role")
    if adjudicator_submission["role"] != "adjudicator":
        raise ReceiptError("adjudicator submission has the wrong role")

    case_tokens = [case["blind_case_token"] for case in template["cases"]]
    case_token_set = set(case_tokens)
    annotations_by_case = {token: [] for token in case_tokens}
    for submission in reviewer_submissions:
        for decision in submission["decisions"]:
            token = decision["blind_case_token"]
            if token not in case_token_set:
                raise ReceiptError("reviewer submission contains an unknown blind case")
            annotations_by_case[token].append(
                {
                    "reviewer_token": submission["participant_token"],
                    "expected_reason_codes": decision["expected_reason_codes"],
                    "completed_at_ms": decision["completed_at_ms"],
                }
            )
    minimum_reviewers = template["protocol"]["minimum_reviewers_per_case"]
    if any(
        len(annotations) < minimum_reviewers
        for annotations in annotations_by_case.values()
    ):
        raise ReceiptError("reviewer submissions do not cover every case")

    adjudication_by_case = {}
    for decision in adjudicator_submission["decisions"]:
        token = decision["blind_case_token"]
        if token not in case_token_set or token in adjudication_by_case:
            raise ReceiptError("adjudicator submission contains an invalid blind case")
        adjudication_by_case[token] = {
            "adjudicator_token": adjudicator_submission["participant_token"],
            "expected_reason_codes": decision["expected_reason_codes"],
            "completed_at_ms": decision["completed_at_ms"],
        }
    if set(adjudication_by_case) != case_token_set:
        raise ReceiptError("adjudicator submission does not cover every case")

    reviewers = [
        {
            "reviewer_token": submission["participant_token"],
            "affiliation_token": submission["affiliation_token"],
            "role": submission["role"],
        }
        for submission in [*reviewer_submissions, adjudicator_submission]
    ]
    reviewers.sort(key=lambda reviewer: reviewer["reviewer_token"])
    cases = []
    for token in case_tokens:
        annotations = annotations_by_case[token]
        annotations.sort(key=lambda annotation: annotation["reviewer_token"])
        cases.append(
            {
                "blind_case_token": token,
                "annotations": annotations,
                "adjudication": adjudication_by_case[token],
            }
        )
    return {
        **{field: template[field] for field in REVIEW_BUNDLE_FIELDS - {"reviewers", "cases"}},
        "reviewers": reviewers,
        "cases": cases,
    }


def blank_template_from_bundle(bundle: dict) -> dict:
    template = copy.deepcopy(bundle)
    template["reviewers"] = []
    for case in template["cases"]:
        if not isinstance(case, dict) or "blind_case_token" not in case:
            raise ReceiptError("review bundle case is malformed")
        case["annotations"] = []
        case["adjudication"] = None
    validate_template(template)
    return template


def load_package(package: object, base: Path) -> dict:
    if not isinstance(package, dict) or set(package) != PACKAGE_FIELDS:
        raise ReceiptError("review receipt package fields are invalid")
    result = dict(package)
    for field in (
        "submission",
        "attestation",
        "public_key",
        "timestamp_request",
        "timestamp_response",
        "ca_file",
    ):
        value = package.get(field)
        if not isinstance(value, str) or not value:
            raise ReceiptError(f"review receipt package {field} is invalid")
        path = Path(value)
        result[field] = (base / path).resolve() if not path.is_absolute() else path.resolve()
    chain = package.get("untrusted_chain")
    if chain is not None and (not isinstance(chain, str) or not chain):
        raise ReceiptError("review receipt package untrusted_chain is invalid")
    if chain is None:
        result["untrusted_chain"] = None
    else:
        chain_path = Path(chain)
        result["untrusted_chain"] = (
            (base / chain_path).resolve()
            if not chain_path.is_absolute()
            else chain_path.resolve()
        )
    if not crypto_support.safe_key_id(package.get("expected_key_id", "")):
        raise ReceiptError("review receipt package expected_key_id is invalid")
    if not timestamp_support.lowercase_sha256(
        package.get("expected_signer_spki_sha256")
    ):
        raise ReceiptError("review receipt package signer SPKI digest is invalid")
    if not timestamp_support.safe_oid(package.get("expected_policy_oid")):
        raise ReceiptError("review receipt package policy OID is invalid")
    if not timestamp_support.lowercase_sha256(
        package.get("expected_tsa_spki_sha256")
    ):
        raise ReceiptError("review receipt package TSA SPKI digest is invalid")
    result["revocation_crls"] = resolve_crl_paths(
        package.get("revocation_crls"), base, "review receipt"
    )
    return result


def load_roster_package(package: object, base: Path) -> dict:
    if not isinstance(package, dict) or set(package) != ROSTER_PACKAGE_FIELDS:
        raise ReceiptError("review roster receipt package fields are invalid")
    result = dict(package)
    for field in (
        "roster",
        "attestation",
        "public_key",
        "timestamp_request",
        "timestamp_response",
        "ca_file",
    ):
        value = package.get(field)
        if not isinstance(value, str) or not value:
            raise ReceiptError(f"review roster receipt package {field} is invalid")
        path = Path(value)
        result[field] = (base / path).resolve() if not path.is_absolute() else path.resolve()
    chain = package.get("untrusted_chain")
    if chain is not None and (not isinstance(chain, str) or not chain):
        raise ReceiptError("review roster receipt untrusted_chain is invalid")
    result["untrusted_chain"] = (
        None
        if chain is None
        else (
            (base / Path(chain)).resolve()
            if not Path(chain).is_absolute()
            else Path(chain).resolve()
        )
    )
    if not crypto_support.safe_key_id(package.get("expected_key_id", "")):
        raise ReceiptError("review roster receipt expected_key_id is invalid")
    for field in ("expected_signer_spki_sha256", "expected_tsa_spki_sha256"):
        if not timestamp_support.lowercase_sha256(package.get(field)):
            raise ReceiptError(f"review roster receipt package {field} is invalid")
    if not timestamp_support.safe_oid(package.get("expected_policy_oid")):
        raise ReceiptError("review roster receipt policy OID is invalid")
    result["revocation_crls"] = resolve_crl_paths(
        package.get("revocation_crls"), base, "review roster receipt"
    )
    return result


def resolve_crl_paths(value: object, base: Path, label: str) -> list[Path]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= timestamp_support.MAX_CRL_COUNT
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ReceiptError(f"{label} revocation_crls are invalid")
    paths = []
    for item in value:
        path = Path(item)
        paths.append(
            (base / path).resolve() if not path.is_absolute() else path.resolve()
        )
    if len(set(paths)) != len(paths):
        raise ReceiptError(f"{label} repeats a revocation CRL path")
    return paths


def load_study_timestamp_package(package: object, base: Path) -> dict:
    if not isinstance(package, dict) or set(package) != STUDY_TIMESTAMP_PACKAGE_FIELDS:
        raise ReceiptError("study timestamp receipt package fields are invalid")
    result = dict(package)
    for field in ("commitment", "timestamp_request", "timestamp_response", "ca_file"):
        value = package.get(field)
        if not isinstance(value, str) or not value:
            raise ReceiptError(f"study timestamp receipt {field} is invalid")
        path = Path(value)
        result[field] = (
            (base / path).resolve() if not path.is_absolute() else path.resolve()
        )
    chain = package.get("untrusted_chain")
    if chain is not None and (not isinstance(chain, str) or not chain):
        raise ReceiptError("study timestamp receipt untrusted_chain is invalid")
    result["untrusted_chain"] = (
        None
        if chain is None
        else (
            (base / Path(chain)).resolve()
            if not Path(chain).is_absolute()
            else Path(chain).resolve()
        )
    )
    result["revocation_crls"] = resolve_crl_paths(
        package.get("revocation_crls"), base, "study timestamp receipt"
    )
    if not timestamp_support.safe_oid(package.get("expected_policy_oid")):
        raise ReceiptError("study timestamp receipt policy OID is invalid")
    if not timestamp_support.lowercase_sha256(
        package.get("expected_tsa_spki_sha256")
    ):
        raise ReceiptError("study timestamp receipt TSA SPKI digest is invalid")
    return result


def verify_package(package: dict) -> tuple[dict, dict]:
    submission_raw, submission = read_json(
        package["submission"], MAX_SUBMISSION_BYTES, "temporal review submission"
    )
    validate_submission(submission)
    report = verify_receipt(
        package["submission"],
        package["attestation"],
        package["public_key"],
        package["expected_key_id"],
        package["expected_signer_spki_sha256"],
        package["timestamp_request"],
        package["timestamp_response"],
        package["ca_file"],
        package["untrusted_chain"],
        package["expected_policy_oid"],
        package["expected_tsa_spki_sha256"],
        package["revocation_crls"],
    )
    if not hmac.compare_digest(
        sha256(submission_raw).hexdigest(), report["submission_file_sha256"]
    ):
        raise ReceiptError("review submission changed while it was being verified")
    return report, submission


def validate_study_timestamp(payload: dict) -> None:
    if (
        payload.get("schema_version") != STUDY_TIMESTAMP_SCHEMA_VERSION
        or payload.get("status") != "pass"
        or payload.get("timestamp_protocol") != "RFC3161"
        or payload.get("trusted_timestamp_assurance") != TIMESTAMP_ASSURANCE
        or payload.get("message_imprint_algorithm") != "sha256"
        or payload.get("certificate_validation_time_basis") != "tsa_gen_time"
        or payload.get("revocation_assurance")
        != timestamp_support.REVOCATION_ASSURANCE
        or payload.get("request_nonce_present") is not True
    ):
        raise ReceiptError("study timestamp verification is not high assurance")
    timestamp_support.validate_revocation_claims(payload)
    timestamp_support.validate_selected_chain_claims(payload)
    timestamp_support.validate_trusted_time_claims(payload)
    for field in (
        "commitment_canonical_sha256",
        "preregistration_canonical_sha256",
        "packet_canonical_sha256",
        "response_sha256",
    ):
        if not timestamp_support.lowercase_sha256(payload.get(field)):
            raise ReceiptError(f"study timestamp {field} is malformed")
    if not safe_token(payload.get("study_id")):
        raise ReceiptError("study timestamp study_id is invalid")


def verify_chain(index_path: Path, output_path: Path | None = None) -> dict:
    index_raw, index = read_json(
        index_path, MAX_INDEX_BYTES, "temporal review receipt index"
    )
    if set(index) != INDEX_FIELDS or index.get("schema_version") != INDEX_SCHEMA_VERSION:
        raise ReceiptError("temporal review receipt index fields are invalid")
    reviewer_packages_raw = index.get("reviewer_receipts")
    if (
        not isinstance(reviewer_packages_raw, list)
        or not 2 <= len(reviewer_packages_raw) <= MAX_PARTICIPANTS
    ):
        raise ReceiptError("temporal review receipt index reviewer count is invalid")
    base = index_path.parent.resolve()
    review_bundle_value = index.get("review_bundle")
    if not isinstance(review_bundle_value, str):
        raise ReceiptError("temporal review receipt index review bundle path is invalid")
    review_bundle_path = (
        (base / review_bundle_value).resolve()
        if not Path(review_bundle_value).is_absolute()
        else Path(review_bundle_value)
    )
    study_timestamp_package = load_study_timestamp_package(
        index.get("study_timestamp_receipt"), base
    )
    reviewer_packages = [load_package(package, base) for package in reviewer_packages_raw]
    adjudicator_package = load_package(index.get("adjudicator_receipt"), base)
    roster_package = load_roster_package(index.get("review_roster_receipt"), base)
    if output_path is not None:
        package_paths = [
            package[field]
            for package in [*reviewer_packages, adjudicator_package]
            for field in (
                "submission",
                "attestation",
                "public_key",
                "timestamp_request",
                "timestamp_response",
                "ca_file",
                "untrusted_chain",
            )
            if package[field] is not None
        ]
        package_crl_paths = [
            crl
            for package in [*reviewer_packages, adjudicator_package]
            for crl in package["revocation_crls"]
        ]
        roster_paths = [
            roster_package[field]
            for field in (
                "roster",
                "attestation",
                "public_key",
                "timestamp_request",
                "timestamp_response",
                "ca_file",
                "untrusted_chain",
            )
            if roster_package[field] is not None
        ]
        study_paths = [
            study_timestamp_package[field]
            for field in (
                "commitment",
                "timestamp_request",
                "timestamp_response",
                "ca_file",
                "untrusted_chain",
            )
            if study_timestamp_package[field] is not None
        ]
        crypto_support.ensure_distinct_output(
            output_path,
            [
                index_path,
                review_bundle_path,
                *study_paths,
                *study_timestamp_package["revocation_crls"],
                *roster_paths,
                *roster_package["revocation_crls"],
                *package_paths,
                *package_crl_paths,
            ],
        )

    review_bundle_raw, review_bundle = read_json(
        review_bundle_path, MAX_REVIEW_BUNDLE_BYTES, "temporal review bundle"
    )
    template = blank_template_from_bundle(review_bundle)
    study_timestamp = timestamp_support.verify_timestamp(
        study_timestamp_package["commitment"],
        study_timestamp_package["timestamp_request"],
        study_timestamp_package["timestamp_response"],
        study_timestamp_package["ca_file"],
        study_timestamp_package["untrusted_chain"],
        study_timestamp_package["expected_policy_oid"],
        study_timestamp_package["expected_tsa_spki_sha256"],
        study_timestamp_package["revocation_crls"],
    )
    validate_study_timestamp(study_timestamp)

    roster_raw, roster = roster_support.load_roster(roster_package["roster"])
    roster_report = roster_support.verify_roster(
        roster_package["roster"],
        roster_package["attestation"],
        roster_package["public_key"],
        roster_package["expected_key_id"],
        roster_package["expected_signer_spki_sha256"],
        roster_package["timestamp_request"],
        roster_package["timestamp_response"],
        roster_package["ca_file"],
        roster_package["untrusted_chain"],
        roster_package["expected_policy_oid"],
        roster_package["expected_tsa_spki_sha256"],
        roster_package["revocation_crls"],
    )
    if not hmac.compare_digest(
        sha256(roster_raw).hexdigest(), roster_report["roster_file_sha256"]
    ):
        raise ReceiptError("review roster changed while it was being verified")

    reviewer_reports = []
    reviewer_submissions = []
    for package in reviewer_packages:
        report, submission = verify_package(package)
        if report["role"] != "reviewer":
            raise ReceiptError("review receipt index contains a non-reviewer package")
        reviewer_reports.append(report)
        reviewer_submissions.append(submission)
    adjudicator_report, adjudicator_submission = verify_package(adjudicator_package)
    if adjudicator_report["role"] != "adjudicator":
        raise ReceiptError("adjudicator receipt package has the wrong role")

    expected_bundle = assemble_bundle(
        template,
        study_timestamp["commitment_canonical_sha256"],
        reviewer_submissions,
        adjudicator_submission,
    )
    if expected_bundle != review_bundle:
        raise ReceiptError("review bundle does not exactly match the signed submissions")

    study_bindings = (
        ("study_id", "study_id"),
        ("preregistration_canonical_sha256", "preregistration_canonical_sha256"),
        ("packet_canonical_sha256", "packet_canonical_sha256"),
    )
    if any(
        review_bundle[review_field] != study_timestamp[timestamp_field]
        for review_field, timestamp_field in study_bindings
    ):
        raise ReceiptError("review bundle does not match the trusted study timestamp")
    roster_bindings = (
        ("study_id", "study_id"),
        ("preregistration_canonical_sha256", "preregistration_canonical_sha256"),
        ("study_commitment_canonical_sha256", "commitment_canonical_sha256"),
        ("packet_canonical_sha256", "packet_canonical_sha256"),
    )
    if any(
        roster_report[roster_field] != study_timestamp[timestamp_field]
        for roster_field, timestamp_field in roster_bindings
    ) or roster_report["packet_id"] != review_bundle["packet_id"]:
        raise ReceiptError("review roster does not match the trusted study packet")

    reviewer_tokens = [report["participant_token"] for report in reviewer_reports]
    if len(set(reviewer_tokens)) != len(reviewer_tokens):
        raise ReceiptError("review receipt chain repeats a reviewer")
    signer_spki = [report["public_key_spki_sha256"] for report in reviewer_reports]
    signer_spki.append(adjudicator_report["public_key_spki_sha256"])
    if len(set(signer_spki)) != len(signer_spki):
        raise ReceiptError("review participants must use distinct signing keys")
    key_ids = [report["key_id"] for report in reviewer_reports]
    key_ids.append(adjudicator_report["key_id"])
    if len(set(key_ids)) != len(key_ids):
        raise ReceiptError("review participants must use distinct key identifiers")
    all_reports = [*reviewer_reports, adjudicator_report]
    all_submissions = [*reviewer_submissions, adjudicator_submission]
    roster_by_token = {
        participant["participant_token"]: participant
        for participant in roster["participants"]
    }
    if set(roster_by_token) != {
        report["participant_token"] for report in all_reports
    }:
        raise ReceiptError("review receipts do not match the frozen roster participants")
    for report, submission in zip(all_reports, all_submissions, strict=True):
        participant = roster_by_token[report["participant_token"]]
        if (
            participant["role"] != report["role"]
            or participant["affiliation_token"] != submission["affiliation_token"]
            or participant["signing_key_id"] != report["key_id"]
            or participant["signing_key_spki_sha256"]
            != report["public_key_spki_sha256"]
        ):
            raise ReceiptError("review receipt identity does not match the frozen roster")
    expected_signer_set_sha256 = sha256(
        "\n".join(sorted(signer_spki)).encode("ascii")
    ).hexdigest()
    if not hmac.compare_digest(
        expected_signer_set_sha256,
        roster_report["participant_signer_spki_set_sha256"],
    ):
        raise ReceiptError("review receipt signer set does not match the frozen roster")

    expected_links = sorted(
        (
            {
                "participant_token": report["participant_token"],
                "submission_attestation_sha256": report[
                    "submission_attestation_sha256"
                ],
                "timestamp_response_sha256": report["response_sha256"],
            }
            for report in reviewer_reports
        ),
        key=lambda link: link["participant_token"],
    )
    if adjudicator_submission["reviewer_receipt_links"] != expected_links:
        raise ReceiptError("adjudicator submission does not bind the exact reviewer receipts")

    commitment_upper = study_timestamp["latest_trusted_time_unix_ms"]
    roster_lower = roster_report["earliest_trusted_time_unix_ms"]
    roster_upper = roster_report["latest_trusted_time_unix_ms"]
    reviewer_lower = min(
        report["earliest_trusted_time_unix_ms"] for report in reviewer_reports
    )
    reviewer_upper = max(
        report["latest_trusted_time_unix_ms"] for report in reviewer_reports
    )
    adjudicator_lower = adjudicator_report["earliest_trusted_time_unix_ms"]
    adjudicator_upper = adjudicator_report["latest_trusted_time_unix_ms"]
    if commitment_upper >= reviewer_lower:
        raise ReceiptError("study commitment time interval overlaps reviewer receipts")
    if commitment_upper >= roster_lower:
        raise ReceiptError("study commitment time interval overlaps the review roster")
    if reviewer_upper >= adjudicator_lower:
        raise ReceiptError("reviewer receipt intervals overlap adjudication")
    reviewer_decision_times = [
        decision["completed_at_ms"]
        for submission in reviewer_submissions
        for decision in submission["decisions"]
    ]
    if min(reviewer_decision_times) <= commitment_upper:
        raise ReceiptError("a reviewer decision predates the trusted study commitment")
    if roster_upper >= min(reviewer_decision_times):
        raise ReceiptError("review roster was not frozen before reviewer decisions")
    for report, submission in zip(reviewer_reports, reviewer_submissions, strict=True):
        if max(
            decision["completed_at_ms"] for decision in submission["decisions"]
        ) >= report["earliest_trusted_time_unix_ms"]:
            raise ReceiptError("a reviewer decision is not earlier than its receipt")
    adjudication_times = [
        decision["completed_at_ms"]
        for decision in adjudicator_submission["decisions"]
    ]
    if min(adjudication_times) <= reviewer_upper:
        raise ReceiptError("an adjudication decision predates the reviewer receipts")
    if max(adjudication_times) >= adjudicator_lower:
        raise ReceiptError("an adjudication decision is not earlier than its receipt")

    receipt_spki_set_sha256 = expected_signer_set_sha256
    tsa_spki = {
        report["tsa_signer_spki_sha256"]
        for report in [*reviewer_reports, adjudicator_report]
    }
    tsa_spki.add(roster_report["tsa_signer_spki_sha256"])
    timestamp_reports = [
        study_timestamp,
        roster_report,
        *reviewer_reports,
        adjudicator_report,
    ]
    for report in timestamp_reports:
        timestamp_support.validate_revocation_claims(report)
    revocation_crl_digests = sorted(
        {
            digest
            for report in timestamp_reports
            for digest in report["revocation_crl_der_sha256s"]
        }
    )
    return {
        "schema_version": CHAIN_VERIFICATION_SCHEMA_VERSION,
        "status": "pass",
        "chronology_assurance": CHAIN_ASSURANCE,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "timestamp_protocol": "RFC3161",
        "message_imprint_algorithm": "sha256",
        "certificate_validation_time_basis": "tsa_gen_time",
        "revocation_assurance": timestamp_support.REVOCATION_ASSURANCE,
        "revocation_evidence_kind": timestamp_support.REVOCATION_EVIDENCE_KIND,
        "revocation_validation_time_basis": "tsa_gen_time",
        "revocation_scope": "full_non_anchor_chain",
        "revocation_network_fetch_used": False,
        "revocation_delta_crls_used": False,
        "revocation_indirect_crls_used": False,
        "revocation_checked_timestamp_count": len(timestamp_reports),
        "revocation_unique_crl_count": len(revocation_crl_digests),
        "revocation_crl_evidence_set_sha256": sha256(
            "\n".join(revocation_crl_digests).encode("ascii")
        ).hexdigest(),
        "study_id": review_bundle["study_id"],
        "preregistration_canonical_sha256": review_bundle[
            "preregistration_canonical_sha256"
        ],
        "study_commitment_canonical_sha256": study_timestamp[
            "commitment_canonical_sha256"
        ],
        "packet_id": review_bundle["packet_id"],
        "packet_canonical_sha256": review_bundle["packet_canonical_sha256"],
        "review_bundle_file_sha256": sha256(review_bundle_raw).hexdigest(),
        "review_bundle_canonical_sha256": sha256(
            json.dumps(
                review_bundle,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
        "receipt_index_sha256": sha256(index_raw).hexdigest(),
        "study_timestamp_response_sha256": study_timestamp["response_sha256"],
        "study_timestamp_revocation_crl_set_sha256": study_timestamp[
            "revocation_crl_set_sha256"
        ],
        "roster_assurance": roster_report["roster_assurance"],
        "roster_canonical_sha256": roster_report["roster_canonical_sha256"],
        "roster_attestation_sha256": roster_report["roster_attestation_sha256"],
        "roster_timestamp_response_sha256": roster_report["response_sha256"],
        "roster_coordinator_public_key_spki_sha256": roster_report[
            "coordinator_public_key_spki_sha256"
        ],
        "governance_record_count": roster_report["governance_record_count"],
        "governance_record_set_sha256": roster_report[
            "governance_record_set_sha256"
        ],
        "roster_changes_after_timestamp_forbidden": roster_report[
            "roster_changes_after_timestamp_forbidden"
        ],
        "reviewer_receipt_count": len(reviewer_reports),
        "distinct_reviewer_signer_count": len(set(signer_spki[:-1])),
        "distinct_receipt_signer_count": len(set(signer_spki)),
        "distinct_reviewer_affiliation_count": len(
            {submission["affiliation_token"] for submission in reviewer_submissions}
        ),
        "distinct_participant_affiliation_count": len(
            {
                submission["affiliation_token"]
                for submission in [*reviewer_submissions, adjudicator_submission]
            }
        ),
        "adjudicator_receipt_count": 1,
        "reviewed_case_count": len(review_bundle["cases"]),
        "reviewer_decision_count": sum(
            report["decision_count"] for report in reviewer_reports
        ),
        "adjudication_decision_count": adjudicator_report["decision_count"],
        "receipt_signer_spki_set_sha256": receipt_spki_set_sha256,
        "participant_signer_spki_set_sha256": roster_report[
            "participant_signer_spki_set_sha256"
        ],
        "receipt_timestamp_authority_count": len(tsa_spki),
        "commitment_latest_trusted_time_unix_ms": commitment_upper,
        "roster_earliest_trusted_time_unix_ms": roster_lower,
        "roster_latest_trusted_time_unix_ms": roster_upper,
        "reviewer_earliest_trusted_time_unix_ms": reviewer_lower,
        "reviewer_latest_trusted_time_unix_ms": reviewer_upper,
        "adjudicator_earliest_trusted_time_unix_ms": adjudicator_lower,
        "adjudicator_latest_trusted_time_unix_ms": adjudicator_upper,
        "commitment_before_review_receipts": True,
        "commitment_before_roster": True,
        "roster_before_review_decisions": True,
        "review_receipts_before_adjudication": True,
        "adjudicator_binds_exact_reviewer_receipts": True,
        "review_decisions_after_commitment": True,
        "review_decisions_before_receipts": True,
        "adjudication_after_review_receipts": True,
        "adjudication_before_receipt": True,
        "privacy": {
            "participant_tokens_exported": False,
            "affiliation_tokens_exported": False,
            "individual_participant_key_digests_exported": False,
            "governance_record_digests_exported": False,
            "case_tokens_exported": False,
            "decision_labels_exported": False,
            "raw_text_present": False,
        },
    }


def package_from_args(args: argparse.Namespace) -> dict:
    return {
        "submission": Path(args.submission),
        "attestation": Path(args.attestation),
        "public_key": Path(args.public_key),
        "expected_key_id": args.expected_key_id,
        "expected_signer_spki_sha256": args.expected_signer_spki_sha256,
        "timestamp_request": Path(args.timestamp_request),
        "timestamp_response": Path(args.timestamp_response),
        "ca_file": Path(args.ca_file),
        "untrusted_chain": Path(args.untrusted_chain) if args.untrusted_chain else None,
        "revocation_crls": [Path(path) for path in args.revocation_crl],
        "expected_policy_oid": args.expected_policy_oid,
        "expected_tsa_spki_sha256": args.expected_tsa_spki_sha256,
    }


def print_or_write_report(report: dict, output_value: str | None, label: str) -> None:
    if output_value:
        output = Path(output_value)
        crypto_support.write_json_atomic(output, report)
        print(f"{label} written to {output} (status=pass)")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))


def main() -> int:
    args = parse_args()
    try:
        if args.command == "sign":
            output = Path(args.output)
            crypto_support.ensure_distinct_output(
                output, [Path(args.submission), Path(args.private_key)]
            )
            attestation = sign_submission(
                Path(args.submission), Path(args.private_key), args.key_id
            )
            crypto_support.write_json_atomic(output, attestation)
            print(f"temporal review submission attestation written to {output}")
            return 0

        if args.command == "request":
            output = Path(args.output)
            attestation_raw, _ = load_attestation(Path(args.attestation))
            crypto_support.ensure_distinct_output(output, [Path(args.attestation)])
            request = timestamp_support.create_request_for_document(
                attestation_raw, args.policy_oid
            )
            timestamp_support.write_bytes_atomic(output, request)
            print(f"temporal review RFC 3161 request written to {output}")
            return 0

        if args.command == "verify":
            package = package_from_args(args)
            report, _ = verify_package(package)
            if args.output:
                crypto_support.ensure_distinct_output(
                    Path(args.output),
                    [
                        package[field]
                        for field in (
                            "submission",
                            "attestation",
                            "public_key",
                            "timestamp_request",
                            "timestamp_response",
                            "ca_file",
                            "untrusted_chain",
                        )
                        if package[field] is not None
                    ]
                    + package["revocation_crls"],
                )
            print_or_write_report(report, args.output, "temporal review receipt verification")
            return 0

        if args.command == "assemble":
            output = Path(args.output)
            _, template = read_json(
                Path(args.template), MAX_REVIEW_BUNDLE_BYTES, "temporal review template"
            )
            commitment_raw = crypto_support.read_bounded(
                Path(args.study_commitment),
                study_support.MAX_COMMITMENT_BYTES,
                "temporal study commitment",
            )
            commitment = study_support.load_json(
                commitment_raw, "temporal study commitment"
            )
            study_support.validate_commitment(commitment)
            commitment_digest = sha256(
                study_support.canonical_commitment(commitment)
            ).hexdigest()
            reviewer_submissions = [
                read_json(
                    Path(path), MAX_SUBMISSION_BYTES, "reviewer submission"
                )[1]
                for path in args.reviewer_submission
            ]
            adjudicator_submission = read_json(
                Path(args.adjudicator_submission),
                MAX_SUBMISSION_BYTES,
                "adjudicator submission",
            )[1]
            bundle = assemble_bundle(
                template,
                commitment_digest,
                reviewer_submissions,
                adjudicator_submission,
            )
            protected = [
                Path(args.template),
                Path(args.study_commitment),
                Path(args.adjudicator_submission),
                *(Path(path) for path in args.reviewer_submission),
            ]
            crypto_support.ensure_distinct_output(output, protected)
            crypto_support.write_json_atomic(output, bundle)
            print(f"temporal review bundle written to {output}")
            return 0

        output = Path(args.output) if args.output else None
        report = verify_chain(Path(args.index), output)
        print_or_write_report(
            report, args.output, "temporal review receipt-chain verification"
        )
        return 0
    except (ReceiptError, UnicodeDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1 if getattr(args, "require_pass", False) else 2


if __name__ == "__main__":
    sys.exit(main())
