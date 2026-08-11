#!/usr/bin/env python3

import argparse
import base64
import binascii
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


ROSTER_SCHEMA_VERSION = "aura.military.temporal_review_roster.v1"
ATTESTATION_SCHEMA_VERSION = "aura.military.temporal_review_roster_attestation.v1"
VERIFICATION_SCHEMA_VERSION = "aura.military.temporal_review_roster_verification.v2"
SIGNATURE_ALGORITHM = "Ed25519"
ROSTER_ASSURANCE = "signed_rfc3161_precommitted"
SIGNED_PAYLOAD_DOMAIN = b"aura.temporal-review.roster-attestation.v1\x00"

MAX_ROSTER_BYTES = 1024 * 1024
MAX_ATTESTATION_BYTES = 128 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_PARTICIPANTS = 32

ROSTER_FIELDS = {
    "schema_version",
    "roster_id",
    "study_id",
    "preregistration_canonical_sha256",
    "study_commitment_canonical_sha256",
    "packet_id",
    "packet_canonical_sha256",
    "protocol",
    "participants",
}
PROTOCOL_FIELDS = {
    "distinct_reviewer_affiliations",
    "independent_adjudicator",
    "conflict_screening_records",
    "blinding_acknowledgements",
    "post_timestamp_changes_forbidden",
}
PARTICIPANT_FIELDS = {
    "participant_token",
    "affiliation_token",
    "role",
    "signing_key_id",
    "signing_key_spki_sha256",
    "eligibility_record_sha256",
    "affiliation_evidence_sha256",
    "conflict_declaration_sha256",
    "blinding_acknowledgement_sha256",
}
ATTESTATION_FIELDS = {
    "schema_version",
    "signature_algorithm",
    "key_id",
    "roster_id",
    "study_id",
    "packet_id",
    "roster_file_sha256",
    "roster_canonical_sha256",
    "public_key_spki_sha256",
    "signature_base64",
}

RosterError = crypto_support.AttestationError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Sign, timestamp, and verify a privacy-minimized AURA temporal-review roster."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign_parser = subparsers.add_parser("sign", help="Sign one frozen roster.")
    sign_parser.add_argument("--roster", required=True)
    sign_parser.add_argument("--private-key", required=True)
    sign_parser.add_argument("--key-id", required=True)
    sign_parser.add_argument("--output", required=True)

    request_parser = subparsers.add_parser(
        "request", help="Create an RFC 3161 request for the signed roster attestation."
    )
    request_parser.add_argument("--attestation", required=True)
    request_parser.add_argument("--policy-oid", required=True)
    request_parser.add_argument("--output", required=True)

    verify_parser = subparsers.add_parser(
        "verify", help="Verify the roster signature and trusted timestamp."
    )
    verify_parser.add_argument("--roster", required=True)
    verify_parser.add_argument("--attestation", required=True)
    verify_parser.add_argument("--public-key", required=True)
    verify_parser.add_argument("--expected-key-id", required=True)
    verify_parser.add_argument("--expected-signer-spki-sha256", required=True)
    verify_parser.add_argument("--timestamp-request", required=True)
    verify_parser.add_argument("--timestamp-response", required=True)
    verify_parser.add_argument("--ca-file", required=True)
    verify_parser.add_argument("--untrusted-chain", default=None)
    verify_parser.add_argument("--revocation-crl", action="append", required=True)
    verify_parser.add_argument("--expected-policy-oid", required=True)
    verify_parser.add_argument("--expected-tsa-spki-sha256", required=True)
    verify_parser.add_argument("--output", default=None)
    verify_parser.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def safe_token(value: object, *, maximum: int = 64) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and 8 <= len(value) <= maximum
        and all(character.isalnum() or character in "_.-" for character in value)
    )


def load_roster(path: Path) -> tuple[bytes, dict]:
    raw = crypto_support.read_bounded(path, MAX_ROSTER_BYTES, "temporal review roster")
    payload = study_support.load_json(raw, "temporal review roster")
    validate_roster(payload)
    return raw, payload


def validate_roster(payload: dict) -> None:
    if set(payload) != ROSTER_FIELDS or payload.get("schema_version") != ROSTER_SCHEMA_VERSION:
        raise RosterError("temporal review roster fields are invalid")
    for field in ("roster_id", "study_id", "packet_id"):
        if not safe_token(payload.get(field)):
            raise RosterError(f"temporal review roster {field} is invalid")
    for field in (
        "preregistration_canonical_sha256",
        "study_commitment_canonical_sha256",
        "packet_canonical_sha256",
    ):
        if not timestamp_support.lowercase_sha256(payload.get(field)):
            raise RosterError(f"temporal review roster {field} is malformed")
    protocol = payload.get("protocol")
    if not isinstance(protocol, dict) or set(protocol) != PROTOCOL_FIELDS:
        raise RosterError("temporal review roster protocol fields are invalid")
    if any(protocol.get(field) is not True for field in PROTOCOL_FIELDS):
        raise RosterError("temporal review roster protocol is not high assurance")

    participants = payload.get("participants")
    if not isinstance(participants, list) or not 3 <= len(participants) <= MAX_PARTICIPANTS:
        raise RosterError("temporal review roster participant count is invalid")
    observed_tokens = []
    affiliations = set()
    key_ids = set()
    signer_spki = set()
    governance_records = set()
    reviewer_count = 0
    adjudicator_count = 0
    for participant in participants:
        if not isinstance(participant, dict) or set(participant) != PARTICIPANT_FIELDS:
            raise RosterError("temporal review roster participant fields are invalid")
        for field in ("participant_token", "affiliation_token", "signing_key_id"):
            if not safe_token(participant.get(field)):
                raise RosterError(f"temporal review roster participant {field} is invalid")
        role = participant.get("role")
        if role == "reviewer":
            reviewer_count += 1
        elif role == "adjudicator":
            adjudicator_count += 1
        else:
            raise RosterError("temporal review roster participant role is invalid")
        for field in (
            "signing_key_spki_sha256",
            "eligibility_record_sha256",
            "affiliation_evidence_sha256",
            "conflict_declaration_sha256",
            "blinding_acknowledgement_sha256",
        ):
            if not timestamp_support.lowercase_sha256(participant.get(field)):
                raise RosterError(f"temporal review roster participant {field} is malformed")
        participant_governance_records = {
            participant[field]
            for field in (
                "eligibility_record_sha256",
                "affiliation_evidence_sha256",
                "conflict_declaration_sha256",
                "blinding_acknowledgement_sha256",
            )
        }
        if (
            len(participant_governance_records) != 4
            or governance_records.intersection(participant_governance_records)
        ):
            raise RosterError("temporal review governance records must be distinct")
        governance_records.update(participant_governance_records)
        token = participant["participant_token"]
        affiliation = participant["affiliation_token"]
        key_id = participant["signing_key_id"]
        spki = participant["signing_key_spki_sha256"]
        if affiliation in affiliations or key_id in key_ids or spki in signer_spki:
            raise RosterError("temporal review roster identities must be distinct")
        observed_tokens.append(token)
        affiliations.add(affiliation)
        key_ids.add(key_id)
        signer_spki.add(spki)
    if observed_tokens != sorted(set(observed_tokens)):
        raise RosterError("temporal review roster participants must be unique and sorted")
    if reviewer_count < 2 or adjudicator_count != 1:
        raise RosterError("temporal review roster requires reviewers and one adjudicator")


def canonical_roster(payload: dict) -> bytes:
    validate_roster(payload)
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
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
        raise RosterError(
            "roster private key is missing, inaccessible, or a symbolic link"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RosterError("roster private key must be a regular file")
        if not 1 <= metadata.st_size <= MAX_KEY_BYTES:
            raise RosterError("roster private key size is invalid")
        if os.name != "nt" and metadata.st_mode & 0o077:
            raise RosterError(
                "roster private key permissions must not allow group or world access"
            )
        raw = bytearray()
        while len(raw) <= MAX_KEY_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_KEY_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if not 1 <= len(raw) <= MAX_KEY_BYTES:
            raise RosterError("roster private key size is invalid")
        return bytes(raw)
    finally:
        os.close(descriptor)


def roster_claims(raw: bytes, roster: dict, public_key_der: bytes, key_id: str) -> dict:
    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "roster_id": roster["roster_id"],
        "study_id": roster["study_id"],
        "packet_id": roster["packet_id"],
        "roster_file_sha256": sha256(raw).hexdigest(),
        "roster_canonical_sha256": sha256(canonical_roster(roster)).hexdigest(),
        "public_key_spki_sha256": sha256(public_key_der).hexdigest(),
    }


def canonical_attestation_claims(payload: dict) -> bytes:
    claims = {
        field: payload[field]
        for field in sorted(ATTESTATION_FIELDS - {"signature_base64"})
    }
    return SIGNED_PAYLOAD_DOMAIN + json.dumps(
        claims, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def sign_roster(roster_path: Path, private_key_path: Path, key_id: str) -> dict:
    if not crypto_support.safe_key_id(key_id):
        raise RosterError("roster key_id is invalid")
    raw, roster = load_roster(roster_path)
    private_key = read_private_key(private_key_path)
    with tempfile.TemporaryDirectory() as temporary_directory:
        key_snapshot = Path(temporary_directory) / "roster-private-key.pem"
        timestamp_support.write_bytes_atomic(key_snapshot, private_key)
        if os.name != "nt":
            key_snapshot.chmod(0o600)
        public_key_der = crypto_support.public_key_der_from_private(key_snapshot)
        attestation = roster_claims(raw, roster, public_key_der, key_id)
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
        raise RosterError("OpenSSL returned a malformed Ed25519 roster signature")
    attestation["signature_base64"] = base64.b64encode(signature).decode("ascii")
    return attestation


def load_attestation(path: Path) -> tuple[bytes, dict]:
    raw = crypto_support.read_bounded(
        path, MAX_ATTESTATION_BYTES, "temporal review roster attestation"
    )
    payload = study_support.load_json(raw, "temporal review roster attestation")
    if set(payload) != ATTESTATION_FIELDS:
        raise RosterError("temporal review roster attestation fields are invalid")
    if (
        payload.get("schema_version") != ATTESTATION_SCHEMA_VERSION
        or payload.get("signature_algorithm") != SIGNATURE_ALGORITHM
        or not crypto_support.safe_key_id(payload.get("key_id", ""))
    ):
        raise RosterError("temporal review roster attestation is unsupported")
    for field in ("roster_id", "study_id", "packet_id"):
        if not safe_token(payload.get(field)):
            raise RosterError(f"temporal review roster attestation {field} is invalid")
    for field in (
        "roster_file_sha256",
        "roster_canonical_sha256",
        "public_key_spki_sha256",
    ):
        if not timestamp_support.lowercase_sha256(payload.get(field)):
            raise RosterError(f"temporal review roster attestation {field} is malformed")
    try:
        signature = base64.b64decode(payload.get("signature_base64", ""), validate=True)
    except (binascii.Error, ValueError) as error:
        raise RosterError("temporal review roster signature is malformed") from error
    if len(signature) != 64:
        raise RosterError("temporal review roster signature is malformed")
    return raw, payload


def verify_roster(
    roster_path: Path,
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
    if not crypto_support.safe_key_id(expected_key_id):
        raise RosterError("expected roster key_id is invalid")
    if not timestamp_support.lowercase_sha256(expected_signer_spki_sha256):
        raise RosterError("expected roster signer SPKI digest is malformed")
    roster_raw, roster = load_roster(roster_path)
    attestation_raw, attestation = load_attestation(attestation_path)
    public_key_raw = crypto_support.read_bounded(
        public_key_path, MAX_KEY_BYTES, "roster public key"
    )
    with tempfile.TemporaryDirectory() as temporary_directory:
        public_key_snapshot = Path(temporary_directory) / "roster-public-key.pem"
        timestamp_support.write_bytes_atomic(public_key_snapshot, public_key_raw)
        public_key_der = crypto_support.public_key_der_from_public(public_key_snapshot)
        expected_claims = roster_claims(
            roster_raw, roster, public_key_der, expected_key_id
        )
        for field, expected in expected_claims.items():
            actual = attestation.get(field)
            matches = (
                hmac.compare_digest(actual, expected)
                if isinstance(actual, str) and isinstance(expected, str)
                else actual == expected
            )
            if not matches:
                raise RosterError(f"roster does not match attested field {field}")
        signer_spki = sha256(public_key_der).hexdigest()
        if not hmac.compare_digest(signer_spki, expected_signer_spki_sha256):
            raise RosterError("roster signer does not match the expected SPKI digest")
        participant_key_ids = {
            participant["signing_key_id"] for participant in roster["participants"]
        }
        participant_spki = {
            participant["signing_key_spki_sha256"]
            for participant in roster["participants"]
        }
        if expected_key_id in participant_key_ids or signer_spki in participant_spki:
            raise RosterError(
                "roster coordinator key must be distinct from participant keys"
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
    roster_attestation_sha256 = timestamp.pop("timestamped_document_sha256")
    participants = roster["participants"]
    reviewers = [participant for participant in participants if participant["role"] == "reviewer"]
    governance_digests = sorted(
        participant[field]
        for participant in participants
        for field in (
            "eligibility_record_sha256",
            "affiliation_evidence_sha256",
            "conflict_declaration_sha256",
            "blinding_acknowledgement_sha256",
        )
    )
    participant_spki = sorted(
        participant["signing_key_spki_sha256"] for participant in participants
    )
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": "pass",
        "roster_assurance": ROSTER_ASSURANCE,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": expected_key_id,
        "study_id": roster["study_id"],
        "preregistration_canonical_sha256": roster[
            "preregistration_canonical_sha256"
        ],
        "study_commitment_canonical_sha256": roster[
            "study_commitment_canonical_sha256"
        ],
        "packet_id": roster["packet_id"],
        "packet_canonical_sha256": roster["packet_canonical_sha256"],
        "roster_id": roster["roster_id"],
        "roster_file_sha256": sha256(roster_raw).hexdigest(),
        "roster_canonical_sha256": sha256(canonical_roster(roster)).hexdigest(),
        "roster_attestation_sha256": roster_attestation_sha256,
        "coordinator_public_key_spki_sha256": signer_spki,
        "participant_count": len(participants),
        "reviewer_count": len(reviewers),
        "adjudicator_count": 1,
        "distinct_affiliation_count": len(
            {participant["affiliation_token"] for participant in participants}
        ),
        "distinct_participant_signer_count": len(set(participant_spki)),
        "participant_signer_spki_set_sha256": sha256(
            "\n".join(participant_spki).encode("ascii")
        ).hexdigest(),
        "governance_record_count": len(governance_digests),
        "governance_record_set_sha256": sha256(
            "\n".join(governance_digests).encode("ascii")
        ).hexdigest(),
        "roster_changes_after_timestamp_forbidden": True,
        "privacy": {
            "participant_tokens_exported": False,
            "affiliation_tokens_exported": False,
            "participant_key_digests_exported": False,
            "governance_record_digests_exported": False,
            "personal_identifiers_present": False,
            "raw_text_present": False,
        },
        **timestamp,
    }


def main() -> int:
    args = parse_args()
    try:
        if args.command == "sign":
            output = Path(args.output)
            crypto_support.ensure_distinct_output(
                output, [Path(args.roster), Path(args.private_key)]
            )
            crypto_support.write_json_atomic(
                output,
                sign_roster(Path(args.roster), Path(args.private_key), args.key_id),
            )
            print(f"temporal review roster attestation written to {output}")
            return 0
        if args.command == "request":
            output = Path(args.output)
            attestation_raw, _ = load_attestation(Path(args.attestation))
            crypto_support.ensure_distinct_output(output, [Path(args.attestation)])
            timestamp_support.write_bytes_atomic(
                output,
                timestamp_support.create_request_for_document(
                    attestation_raw, args.policy_oid
                ),
            )
            print(f"temporal review roster RFC 3161 request written to {output}")
            return 0

        protected = [
            Path(args.roster),
            Path(args.attestation),
            Path(args.public_key),
            Path(args.timestamp_request),
            Path(args.timestamp_response),
            Path(args.ca_file),
        ]
        if args.untrusted_chain:
            protected.append(Path(args.untrusted_chain))
        protected.extend(Path(path) for path in args.revocation_crl)
        if args.output:
            crypto_support.ensure_distinct_output(Path(args.output), protected)
        report = verify_roster(
            Path(args.roster),
            Path(args.attestation),
            Path(args.public_key),
            args.expected_key_id,
            args.expected_signer_spki_sha256,
            Path(args.timestamp_request),
            Path(args.timestamp_response),
            Path(args.ca_file),
            Path(args.untrusted_chain) if args.untrusted_chain else None,
            args.expected_policy_oid,
            args.expected_tsa_spki_sha256,
            [Path(path) for path in args.revocation_crl],
        )
        if args.output:
            crypto_support.write_json_atomic(Path(args.output), report)
            print(f"temporal review roster verification written to {args.output} (status=pass)")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (RosterError, UnicodeDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1 if getattr(args, "require_pass", False) else 2


if __name__ == "__main__":
    sys.exit(main())
