#!/usr/bin/env python3

"""Issue Rust-compatible trusted-time receipts for domain-study artifacts.

This adapter deliberately does not implement a second PKIX or RFC 3161 verifier.
It snapshots the bounded input artifacts, delegates all timestamp, chain, and
historical-revocation checks to ``temporal_study_timestamp``, and signs only the
resulting fail-closed claims.

The timestamped subject must be the exact compact UTF-8 JSON emitted by Rust
``serde_json::to_vec`` for the signed artifact: struct field order is preserved,
there is no insignificant whitespace, and there is no trailing newline.  Its
claim is SHA-256 over those exact bytes.

The bridge never reserializes the subject across language runtimes.  The Rust
result validator compares this byte digest with its typed canonical
serialization and therefore rejects alternate compact encodings fail closed.

The certificate and revocation claims are copied from the shared verifier's
domain-separated aggregates.  The certificate digest binds the selected
leaf-to-root DER chain; the revocation digest binds the sorted complete CRL DER
set.  Their framing is owned by ``temporal_study_timestamp`` so this bridge
cannot silently reinterpret already verified PKIX evidence.
"""

import argparse
import json
import os
import secrets
import stat
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

try:
    from ci import evidence_attestation as crypto_support
    from ci import temporal_study_attestation as attestation_support
    from ci import temporal_study_timestamp as timestamp_support
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import evidence_attestation as crypto_support
    import temporal_study_attestation as attestation_support
    import temporal_study_timestamp as timestamp_support


TRUSTED_TIMESTAMP_SCHEMA_VERSION = "aura.domain.trusted_timestamp_verification.v2"
TRUSTED_TIMESTAMP_PROTOCOL = "rfc3161_trusted_chain"
SIGNED_PAYLOAD_DOMAIN = b"aura.domain.trusted-timestamp.v1\x00"
MAX_SUBJECT_BYTES = 8 * 1024 * 1024
MAX_RUST_U64 = (1 << 64) - 1
SUBJECT_KINDS = (
    "preregistration_attestation",
    "reviewer_receipt",
    "reviewer_agreement_analysis",
    "adjudication_start_authorization",
    "adjudication_receipt",
    "final_evidence_manifest",
)
CLAIM_FIELDS = (
    "schema_version",
    "subject_kind",
    "subject_canonical_sha256",
    "protocol",
    "issued_at_ms",
    "gen_time_submillisecond_micros",
    "accuracy_micros",
    "request_sha256",
    "response_sha256",
    "certificate_chain_sha256",
    "revocation_evidence_sha256",
    "tsa_spki_sha256",
    "tsa_policy_oid",
)

AdapterError = crypto_support.AttestationError


class FrozenAtomicOutput:
    """Bind an output name to one opened directory for the whole operation.

    Resolving an output path before a long RFC 3161 verification leaves a
    TOCTOU window: an attacker can rename the checked parent directory and put
    a symbolic link in its place before the final path-based replace.  This
    writer keeps the original directory descriptor open, creates its temporary
    file relative to that descriptor, and performs the final replace relative
    to the same descriptor.
    """

    def __init__(self, output: Path, protected_paths: list[Path]):
        if output.name in ("", ".", ".."):
            raise AdapterError("output path must name a file")
        lexical_output = Path(os.path.abspath(os.path.normpath(output)))
        lexical_protected = {
            Path(os.path.abspath(os.path.normpath(path))) for path in protected_paths
        }
        if lexical_output in lexical_protected:
            raise AdapterError("output path must not overwrite an adapter input")
        self.output = output
        self._name = output.name
        self._directory_descriptor: int | None = None
        self._protected_identities: frozenset[tuple[int, int]] = frozenset()
        self._written = False

        # Capture the original inputs before binding the output directory.  A
        # hard-link alias must remain protected even if a shared parent is
        # renamed between the two operations.
        initial_protected_identities = {
            self._protected_identity(path) for path in protected_paths
        }

        directory_flags = os.O_RDONLY
        directory_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            self._directory_descriptor = os.open(output.parent, directory_flags)
            directory_metadata = os.fstat(self._directory_descriptor)
            if not stat.S_ISDIR(directory_metadata.st_mode):
                raise AdapterError("output parent is not a directory")
            current_protected_identities = {
                self._protected_identity(path) for path in protected_paths
            }
            self._protected_identities = frozenset(
                initial_protected_identities | current_protected_identities
            )
            self._validate_target()
        except AdapterError:
            self.close()
            raise
        except OSError as error:
            self.close()
            raise AdapterError(
                "output parent is missing, symbolic, or cannot be opened safely: "
                f"{output.parent}"
            ) from error

    @staticmethod
    def _protected_identity(path: Path) -> tuple[int, int]:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise AdapterError(
                f"protected input is missing, symbolic, or unsafe: {path}"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise AdapterError(f"protected input is not a regular file: {path}")
            return metadata.st_dev, metadata.st_ino
        finally:
            os.close(descriptor)

    def _validate_target(self) -> None:
        if self._directory_descriptor is None:
            raise AdapterError("output directory is not open")
        try:
            metadata = os.stat(
                self._name,
                dir_fd=self._directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        except OSError as error:
            raise AdapterError("output target cannot be inspected safely") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise AdapterError("output target must not be a symbolic link")
        if not stat.S_ISREG(metadata.st_mode):
            raise AdapterError("output target must be a regular file")
        if (metadata.st_dev, metadata.st_ino) in self._protected_identities:
            raise AdapterError("output path must not overwrite an adapter input")

    def protect_identities(self, identities: set[tuple[int, int]]) -> None:
        if self._written:
            raise AdapterError("cannot add protected inputs after output is written")
        self._protected_identities = frozenset(
            set(self._protected_identities) | identities
        )
        self._validate_target()

    def write_bytes(self, payload: bytes) -> None:
        if self._directory_descriptor is None:
            raise AdapterError("output directory is not open")
        if self._written:
            raise AdapterError("output may only be written once")
        if not isinstance(payload, bytes):
            raise AdapterError("output payload must be bytes")

        temporary_name = f".aura-timestamp-{secrets.token_hex(16)}.tmp"
        temporary_descriptor: int | None = None
        temporary_exists = False
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            temporary_descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=self._directory_descriptor,
            )
            temporary_exists = True
            offset = 0
            while offset < len(payload):
                written = os.write(temporary_descriptor, payload[offset:])
                if written <= 0:
                    raise AdapterError("output write made no progress")
                offset += written
            os.fsync(temporary_descriptor)
            os.close(temporary_descriptor)
            temporary_descriptor = None

            # Recheck immediately before replacement so a target created or
            # swapped during the expensive verification cannot be a symlink,
            # special file, or hard link to any protected input.
            self._validate_target()
            os.replace(
                temporary_name,
                self._name,
                src_dir_fd=self._directory_descriptor,
                dst_dir_fd=self._directory_descriptor,
            )
            temporary_exists = False
            os.fsync(self._directory_descriptor)
            self._written = True
        except AdapterError:
            raise
        except OSError as error:
            raise AdapterError("output could not be written atomically") from error
        finally:
            if temporary_descriptor is not None:
                os.close(temporary_descriptor)
            if temporary_exists:
                try:
                    os.unlink(temporary_name, dir_fd=self._directory_descriptor)
                except FileNotFoundError:
                    pass

    def close(self) -> None:
        if self._directory_descriptor is not None:
            os.close(self._directory_descriptor)
            self._directory_descriptor = None

    def __enter__(self) -> "FrozenAtomicOutput":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create RFC 3161 requests and issue signed AURA domain-study "
            "trusted timestamp receipts."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    request_parser = subparsers.add_parser(
        "request", help="Create a nonce-bearing DER request over an exact subject."
    )
    request_parser.add_argument("--subject", required=True)
    request_parser.add_argument("--policy-oid", required=True)
    request_parser.add_argument("--output", required=True)

    verify_parser = subparsers.add_parser(
        "verify-sign",
        help="Verify original timestamp evidence and sign the trusted receipt.",
    )
    verify_parser.add_argument("--subject", required=True)
    verify_parser.add_argument("--subject-kind", choices=SUBJECT_KINDS, required=True)
    verify_parser.add_argument("--request", required=True)
    verify_parser.add_argument("--response", required=True)
    verify_parser.add_argument("--ca-file", required=True)
    verify_parser.add_argument("--untrusted-chain", default=None)
    verify_parser.add_argument(
        "--revocation-crl",
        action="append",
        required=True,
        help="Original complete CRL; repeat for every non-anchor chain issuer.",
    )
    verify_parser.add_argument("--expected-policy-oid", required=True)
    verify_parser.add_argument("--expected-tsa-spki-sha256", required=True)
    verify_parser.add_argument("--private-key", required=True)
    verify_parser.add_argument("--key-id", required=True)
    verify_parser.add_argument("--output", required=True)
    verify_parser.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def reject_duplicate_json_fields(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError(f"duplicate JSON field is not allowed: {key}")
        result[key] = value
    return result


def reject_nonfinite_json_number(value: str) -> None:
    raise AdapterError(f"non-finite JSON number is not allowed: {value}")


def validate_compact_subject(raw: bytes) -> bytes:
    try:
        text = raw.decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=reject_duplicate_json_fields,
            parse_constant=reject_nonfinite_json_number,
        )
    except AdapterError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise AdapterError(f"timestamp subject is not strict JSON: {error}") from error
    if not isinstance(payload, dict):
        raise AdapterError("timestamp subject must be a JSON object")
    inside_string = False
    escaped = False
    for character in text:
        if inside_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                inside_string = False
        elif character == '"':
            inside_string = True
        elif character.isspace():
            raise AdapterError(
                "timestamp subject must be compact Rust serde JSON with no whitespace"
            )
    if inside_string or escaped:
        raise AdapterError("timestamp subject is not complete JSON")
    return raw


def read_compact_subject(path: Path) -> bytes:
    raw = crypto_support.read_bounded(path, MAX_SUBJECT_BYTES, "timestamp subject")
    return validate_compact_subject(raw)


def read_compact_subject_with_identity(
    path: Path,
) -> tuple[bytes, tuple[int, int]]:
    raw, identity = crypto_support.read_bounded_with_identity(
        path, MAX_SUBJECT_BYTES, "timestamp subject"
    )
    return validate_compact_subject(raw), identity


def signing_payload(claims: dict, key_id: str) -> bytes:
    """Match ``research_result.rs::signing_payload`` byte for byte."""
    if not isinstance(claims, dict) or set(claims) != set(CLAIM_FIELDS):
        raise AdapterError("trusted timestamp claims must contain the exact field set")
    ordered_claims = {field: claims[field] for field in CLAIM_FIELDS}
    signed_claims = {"key_id": key_id, "claims": ordered_claims}
    return SIGNED_PAYLOAD_DOMAIN + json.dumps(
        signed_claims,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def safe_key_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and all(
            character.isascii()
            and (character.isalnum() or character in "_-.")
            for character in value
        )
    )


def sign_claims(
    claims: dict,
    private_key_path: Path,
    key_id: str,
    *,
    private_key_bytes: bytes | None = None,
) -> dict:
    if not safe_key_id(key_id):
        raise AdapterError(
            "key_id must be 1..128 ASCII alphanumeric, '_', '-', or '.' characters"
        )
    key_bytes = (
        attestation_support.validate_private_key_file(private_key_path)
        if private_key_bytes is None
        else private_key_bytes
    )
    with crypto_support.private_key_snapshot(key_bytes) as key_snapshot:
        public_key_der = timestamp_support.run_openssl(
            ["pkey", "-in", key_snapshot.as_posix(), "-pubout", "-outform", "DER"]
        )
        ed25519_spki_prefix = bytes.fromhex("302a300506032b6570032100")
        if len(public_key_der) != 44 or not public_key_der.startswith(
            ed25519_spki_prefix
        ):
            raise AdapterError("timestamp verifier private key must use Ed25519")
        with tempfile.NamedTemporaryFile() as payload_file:
            payload_file.write(signing_payload(claims, key_id))
            payload_file.flush()
            signature = timestamp_support.run_openssl(
                [
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    key_snapshot.as_posix(),
                    "-in",
                    payload_file.name,
                ]
            )
    if len(signature) != 64:
        raise AdapterError("OpenSSL returned a malformed Ed25519 signature")
    return {"key_id": key_id, "signature_hex": signature.hex()}


def _snapshot_inputs(
    temporary: Path,
    request_raw: bytes,
    response_raw: bytes,
    ca_raw: bytes,
    untrusted_raw: bytes | None,
    crl_raw: list[bytes],
) -> tuple[Path, Path, Path, Path | None, list[Path]]:
    request_path = temporary / "request.tsq"
    response_path = temporary / "response.tsr"
    ca_path = temporary / "trust-anchors.pem"
    untrusted_path = temporary / "untrusted-chain.pem" if untrusted_raw else None
    for path, raw in (
        (request_path, request_raw),
        (response_path, response_raw),
        (ca_path, ca_raw),
    ):
        timestamp_support.write_bytes_atomic(path, raw)
    if untrusted_path is not None and untrusted_raw is not None:
        timestamp_support.write_bytes_atomic(untrusted_path, untrusted_raw)
    crl_paths = []
    for index, raw in enumerate(crl_raw):
        path = temporary / f"revocation-{index:02d}.crl"
        timestamp_support.write_bytes_atomic(path, raw)
        crl_paths.append(path)
    return request_path, response_path, ca_path, untrusted_path, crl_paths


def create_trusted_timestamp_receipt(
    *,
    subject_path: Path,
    subject_kind: str,
    request_path: Path,
    response_path: Path,
    ca_file_path: Path,
    untrusted_chain_path: Path | None,
    revocation_crl_paths: list[Path],
    expected_policy_oid: str,
    expected_tsa_spki_sha256: str,
    private_key_path: Path,
    key_id: str,
    frozen_output: FrozenAtomicOutput | None = None,
) -> dict:
    if subject_kind not in SUBJECT_KINDS:
        raise AdapterError("timestamp subject kind is unsupported")
    if not timestamp_support.safe_oid(expected_policy_oid):
        raise AdapterError("expected timestamp policy OID is malformed")
    if not timestamp_support.lowercase_sha256(expected_tsa_spki_sha256):
        raise AdapterError("expected TSA SPKI SHA-256 is malformed")
    if not safe_key_id(key_id):
        raise AdapterError("timestamp verifier key_id is malformed")
    private_key_bytes, private_key_identity = (
        crypto_support.read_bounded_private_with_identity(
            private_key_path,
            attestation_support.MAX_KEY_BYTES,
            "Ed25519 private key",
        )
    )

    subject, subject_identity = read_compact_subject_with_identity(subject_path)
    request_raw, request_identity = crypto_support.read_bounded_with_identity(
        request_path, timestamp_support.MAX_REQUEST_BYTES, "RFC 3161 request"
    )
    response_raw, response_identity = crypto_support.read_bounded_with_identity(
        response_path, timestamp_support.MAX_RESPONSE_BYTES, "RFC 3161 response"
    )
    ca_raw, ca_identity = crypto_support.read_bounded_with_identity(
        ca_file_path,
        timestamp_support.MAX_CA_BUNDLE_BYTES,
        "RFC 3161 trust-anchor bundle",
    )
    if untrusted_chain_path is not None:
        untrusted_raw, untrusted_identity = crypto_support.read_bounded_with_identity(
            untrusted_chain_path,
            timestamp_support.MAX_UNTRUSTED_CHAIN_BYTES,
            "RFC 3161 untrusted certificate chain",
        )
    else:
        untrusted_raw = None
        untrusted_identity = None
    if not 1 <= len(revocation_crl_paths) <= timestamp_support.MAX_CRL_COUNT:
        raise AdapterError(
            f"revocation evidence requires 1..={timestamp_support.MAX_CRL_COUNT} CRLs"
        )
    resolved_crls = [path.resolve() for path in revocation_crl_paths]
    if len(set(resolved_crls)) != len(resolved_crls):
        raise AdapterError("revocation evidence repeats a CRL path")
    crl_inputs = [
        crypto_support.read_bounded_with_identity(
            path, timestamp_support.MAX_CRL_BYTES, "X.509 revocation CRL"
        )
        for path in revocation_crl_paths
    ]
    crl_raw = [raw for raw, _ in crl_inputs]
    if sum(len(raw) for raw in crl_raw) > timestamp_support.MAX_TOTAL_CRL_BYTES:
        raise AdapterError("X.509 revocation CRL set is too large")
    if frozen_output is not None:
        frozen_output.protect_identities(
            {
                subject_identity,
                request_identity,
                response_identity,
                ca_identity,
                private_key_identity,
                *(identity for _, identity in crl_inputs),
                *(
                    (untrusted_identity,)
                    if untrusted_identity is not None
                    else ()
                ),
            }
        )

    with tempfile.TemporaryDirectory() as temporary_directory:
        snapshots = _snapshot_inputs(
            Path(temporary_directory),
            request_raw,
            response_raw,
            ca_raw,
            untrusted_raw,
            crl_raw,
        )
        verification = timestamp_support.verify_document_timestamp(
            subject,
            snapshots[0],
            snapshots[1],
            snapshots[2],
            snapshots[3],
            expected_policy_oid,
            expected_tsa_spki_sha256,
            snapshots[4],
        )

    timestamp_support.validate_revocation_claims(verification)
    timestamp_support.validate_selected_chain_claims(verification)
    timestamp_support.validate_trusted_time_claims(verification)
    subject_sha256 = sha256(subject).hexdigest()
    issued_at_ms = verification.get("gen_time_unix_ms")
    gen_time_submillisecond_micros = verification.get(
        "gen_time_submillisecond_micros"
    )
    accuracy_micros = verification.get("accuracy_micros")
    certificate_chain_sha256 = verification.get("certificate_chain_sha256")
    revocation_evidence_sha256 = verification.get("revocation_evidence_sha256")
    certificate_chain_der_sha256s = verification.get(
        "certificate_chain_der_sha256s"
    )
    required_sha256 = {
        "timestamped_document_sha256": subject_sha256,
        "request_sha256": sha256(request_raw).hexdigest(),
        "response_sha256": sha256(response_raw).hexdigest(),
        "tsa_signer_spki_sha256": expected_tsa_spki_sha256,
    }
    if any(
        not isinstance(verification.get(field), str)
        or verification[field] != expected
        for field, expected in required_sha256.items()
    ):
        raise AdapterError("RFC 3161 verifier returned inconsistent artifact identities")
    if (
        verification.get("timestamp_protocol") != timestamp_support.TIMESTAMP_PROTOCOL
        or verification.get("trusted_timestamp_assurance")
        != timestamp_support.TRUSTED_TIMESTAMP_ASSURANCE
        or verification.get("message_imprint_algorithm")
        != timestamp_support.HASH_ALGORITHM
        or verification.get("request_nonce_present") is not True
        or verification.get("certificate_validation_time_basis") != "tsa_gen_time"
        or verification.get("certificate_chain_order")
        != "tsa_signer_to_trust_anchor"
        or not isinstance(certificate_chain_der_sha256s, list)
        or not 2
        <= len(certificate_chain_der_sha256s)
        <= timestamp_support.MAX_SELECTED_CERTIFICATE_CHAIN_COUNT
        or any(
            not timestamp_support.lowercase_sha256(digest)
            for digest in certificate_chain_der_sha256s
        )
        or len(set(certificate_chain_der_sha256s))
        != len(certificate_chain_der_sha256s)
        or certificate_chain_der_sha256s[0]
        != verification.get("tsa_signer_certificate_sha256")
        or verification.get("revocation_checked_certificate_count")
        != len(certificate_chain_der_sha256s) - 1
        or certificate_chain_sha256
        != timestamp_support.aggregate_der_digest(
            certificate_chain_der_sha256s,
            timestamp_support.CERTIFICATE_CHAIN_DIGEST_DOMAIN,
            "selected TSA certificate chain",
        )
        or not isinstance(issued_at_ms, int)
        or isinstance(issued_at_ms, bool)
        or issued_at_ms <= 0
        or issued_at_ms > MAX_RUST_U64
        or not isinstance(gen_time_submillisecond_micros, int)
        or isinstance(gen_time_submillisecond_micros, bool)
        or not 0 <= gen_time_submillisecond_micros <= 999
        or not isinstance(accuracy_micros, int)
        or isinstance(accuracy_micros, bool)
        or not 0 < accuracy_micros <= timestamp_support.MAX_TIMESTAMP_ACCURACY_MICROS
        or not timestamp_support.lowercase_sha256(certificate_chain_sha256)
        or not timestamp_support.lowercase_sha256(revocation_evidence_sha256)
        or verification.get("policy_oid") != expected_policy_oid
    ):
        raise AdapterError("RFC 3161 verifier returned claims outside the Rust trust contract")
    exact_time_micros = issued_at_ms * 1_000 + gen_time_submillisecond_micros
    if (
        exact_time_micros < accuracy_micros
        or exact_time_micros > MAX_RUST_U64 - accuracy_micros
    ):
        raise AdapterError("RFC 3161 uncertainty interval is outside Rust u64 time")
    earliest_time_ms = (exact_time_micros - accuracy_micros) // 1_000
    latest_time_ms = (exact_time_micros + accuracy_micros + 999) // 1_000
    if (
        verification.get("earliest_trusted_time_unix_ms")
        != earliest_time_ms
        or verification.get("latest_trusted_time_unix_ms")
        != latest_time_ms
    ):
        raise AdapterError("RFC 3161 verifier returned an inconsistent time interval")

    claims = {
        "schema_version": TRUSTED_TIMESTAMP_SCHEMA_VERSION,
        "subject_kind": subject_kind,
        "subject_canonical_sha256": subject_sha256,
        "protocol": TRUSTED_TIMESTAMP_PROTOCOL,
        "issued_at_ms": issued_at_ms,
        "gen_time_submillisecond_micros": gen_time_submillisecond_micros,
        "accuracy_micros": accuracy_micros,
        "request_sha256": verification["request_sha256"],
        "response_sha256": verification["response_sha256"],
        "certificate_chain_sha256": certificate_chain_sha256,
        "revocation_evidence_sha256": revocation_evidence_sha256,
        "tsa_spki_sha256": verification["tsa_signer_spki_sha256"],
        "tsa_policy_oid": verification["policy_oid"],
    }
    signature = sign_claims(
        claims,
        private_key_path,
        key_id,
        private_key_bytes=private_key_bytes,
    )
    return {"claims": claims, "signature": signature}


def main() -> int:
    args = parse_args()
    try:
        if args.command == "request":
            subject_path = Path(args.subject)
            output = Path(args.output)
            with FrozenAtomicOutput(output, [subject_path]) as frozen_output:
                subject, subject_identity = read_compact_subject_with_identity(
                    subject_path
                )
                frozen_output.protect_identities({subject_identity})
                request = timestamp_support.create_request_for_document(
                    subject, args.policy_oid
                )
                frozen_output.write_bytes(request)
            print(f"domain-study RFC 3161 request written to {output}")
            return 0

        output = Path(args.output)
        protected = [
            Path(args.subject),
            Path(args.request),
            Path(args.response),
            Path(args.ca_file),
            Path(args.private_key),
            *(Path(path) for path in args.revocation_crl),
        ]
        if args.untrusted_chain:
            protected.append(Path(args.untrusted_chain))
        with FrozenAtomicOutput(output, protected) as frozen_output:
            receipt = create_trusted_timestamp_receipt(
                subject_path=Path(args.subject),
                subject_kind=args.subject_kind,
                request_path=Path(args.request),
                response_path=Path(args.response),
                ca_file_path=Path(args.ca_file),
                untrusted_chain_path=(
                    Path(args.untrusted_chain) if args.untrusted_chain else None
                ),
                revocation_crl_paths=[Path(path) for path in args.revocation_crl],
                expected_policy_oid=args.expected_policy_oid,
                expected_tsa_spki_sha256=args.expected_tsa_spki_sha256,
                private_key_path=Path(args.private_key),
                key_id=args.key_id,
                frozen_output=frozen_output,
            )
            serialized_receipt = (
                json.dumps(receipt, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            frozen_output.write_bytes(serialized_receipt)
        print(f"domain-study trusted timestamp receipt written to {output}")
        return 0
    except (AdapterError, UnicodeDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1 if getattr(args, "require_pass", False) else 2


if __name__ == "__main__":
    sys.exit(main())
