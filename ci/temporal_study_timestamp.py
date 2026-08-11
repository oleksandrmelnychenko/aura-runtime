#!/usr/bin/env python3

import argparse
import hmac
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

try:
    from ci import evidence_attestation as crypto_support
    from ci import temporal_study_attestation as study_support
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import evidence_attestation as crypto_support
    import temporal_study_attestation as study_support


VERIFICATION_SCHEMA_VERSION = (
    "aura.military.temporal_study_timestamp_verification.v1"
)
TIMESTAMP_PROTOCOL = "RFC3161"
HASH_ALGORITHM = "sha256"
TRUSTED_TIMESTAMP_ASSURANCE = "rfc3161_trusted_chain"
MAX_COMMITMENT_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_CA_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_UNTRUSTED_CHAIN_BYTES = 4 * 1024 * 1024
MAX_SIGNER_CERTIFICATE_BYTES = 256 * 1024
MAX_FUTURE_SKEW_MS = 5 * 60 * 1000
MAX_DECLARED_CLOCK_SKEW_MS = 5 * 60 * 1000
MAX_TIMESTAMP_ACCURACY_MICROS = 5 * 60 * 1_000_000

TimestampError = crypto_support.AttestationError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create or verify an RFC 3161 timestamp request for an AURA temporal "
            "study commitment."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    request_parser = subparsers.add_parser(
        "request", help="Create a nonce-bearing DER timestamp request."
    )
    request_parser.add_argument("--commitment", required=True)
    request_parser.add_argument("--policy-oid", required=True)
    request_parser.add_argument("--output", required=True)

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a DER timestamp response and its trust chain."
    )
    verify_parser.add_argument("--commitment", required=True)
    verify_parser.add_argument("--request", required=True)
    verify_parser.add_argument("--response", required=True)
    verify_parser.add_argument("--ca-file", required=True)
    verify_parser.add_argument("--untrusted-chain", default=None)
    verify_parser.add_argument("--expected-policy-oid", required=True)
    verify_parser.add_argument("--expected-tsa-spki-sha256", required=True)
    verify_parser.add_argument("--output", default=None)
    verify_parser.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def openssl_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["OPENSSL_CONF"] = os.devnull
    environment["LC_ALL"] = "C"
    return environment


def run_openssl(arguments: list[str], input_bytes: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *arguments],
            input=input_bytes,
            capture_output=True,
            check=False,
            env=openssl_environment(),
        )
    except FileNotFoundError as error:
        raise TimestampError("OpenSSL is required for RFC 3161 verification") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise TimestampError(f"OpenSSL command failed: {detail or 'unknown error'}")
    return result.stdout


def safe_oid(value: object) -> bool:
    if not isinstance(value, str) or not 3 <= len(value) <= 128:
        return False
    components = value.split(".")
    if len(components) < 3 or any(
        not component.isascii()
        or not component.isdigit()
        or (len(component) > 1 and component.startswith("0"))
        for component in components
    ):
        return False
    first = int(components[0])
    second = int(components[1])
    return first in (0, 1, 2) and (first == 2 or second <= 39)


def lowercase_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def read_commitment(path: Path) -> tuple[bytes, dict]:
    raw = crypto_support.read_bounded(
        path, MAX_COMMITMENT_BYTES, "temporal study commitment"
    )
    payload = study_support.load_json(raw, "temporal study commitment")
    study_support.validate_commitment(payload)
    return raw, payload


def single_text_value(text: str, label: str) -> str:
    prefix = f"{label}:"
    values = [
        line[len(prefix) :].strip()
        for line in text.splitlines()
        if line.startswith(prefix)
    ]
    if len(values) != 1 or not values[0]:
        raise TimestampError(f"RFC 3161 text has missing or duplicate {label}")
    return values[0]


def inspect_request(path: Path) -> dict:
    text = run_openssl(["ts", "-query", "-in", path.as_posix(), "-text"]).decode(
        "utf-8", errors="strict"
    )
    request = {
        "version": single_text_value(text, "Version"),
        "hash_algorithm": single_text_value(text, "Hash Algorithm"),
        "policy_oid": single_text_value(text, "Policy OID"),
        "nonce": single_text_value(text, "Nonce"),
        "certificate_required": single_text_value(text, "Certificate required"),
    }
    if request["version"] != "1":
        raise TimestampError("RFC 3161 request version must be 1")
    if request["hash_algorithm"].lower() != HASH_ALGORITHM:
        raise TimestampError("RFC 3161 request must use SHA-256")
    if not safe_oid(request["policy_oid"]):
        raise TimestampError("RFC 3161 request policy OID is malformed")
    if not re.fullmatch(r"0x[0-9A-Fa-f]{16,128}", request["nonce"]):
        raise TimestampError("RFC 3161 request must contain a large nonce")
    if request["certificate_required"].lower() != "yes":
        raise TimestampError("RFC 3161 request must require the TSA certificate")
    return request


def parse_timestamp_ms(value: str) -> int:
    normalized = " ".join(value.split())
    formats = (
        "%b %d %H:%M:%S.%f %Y GMT",
        "%b %d %H:%M:%S %Y GMT",
    )
    for format_string in formats:
        try:
            parsed = datetime.strptime(normalized, format_string).replace(tzinfo=timezone.utc)
            return int(parsed.timestamp() * 1000)
        except ValueError:
            continue
    raise TimestampError("RFC 3161 genTime is not strict UTC text")


def parse_nonnegative_integer(value: str, label: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise TimestampError(f"RFC 3161 {label} is malformed") from error
    if parsed < 0:
        raise TimestampError(f"RFC 3161 {label} must be nonnegative")
    return parsed


def parse_accuracy_micros(value: str) -> int | None:
    if value == "unspecified":
        return None
    pattern = re.compile(
        r"(?:(0x[0-9A-Fa-f]+|[0-9]+) seconds)?"
        r"(?:, )?(?:(0x[0-9A-Fa-f]+|[0-9]+) millis)?"
        r"(?:, )?(?:(0x[0-9A-Fa-f]+|[0-9]+) micros)?"
    )
    match = pattern.fullmatch(value)
    if match is None or all(component is None for component in match.groups()):
        raise TimestampError("RFC 3161 accuracy is malformed")
    seconds, millis, micros = (
        parse_nonnegative_integer(component, "accuracy") if component else 0
        for component in match.groups()
    )
    if millis > 999 or micros > 999:
        raise TimestampError("RFC 3161 accuracy subsecond component is invalid")
    return seconds * 1_000_000 + millis * 1_000 + micros


def inspect_response(path: Path) -> dict:
    text = run_openssl(["ts", "-reply", "-in", path.as_posix(), "-text"]).decode(
        "utf-8", errors="strict"
    )
    status = single_text_value(text, "Status")
    if status != "Granted.":
        raise TimestampError("RFC 3161 response status must be Granted without modifications")
    version = single_text_value(text, "Version")
    policy_oid = single_text_value(text, "Policy OID")
    hash_algorithm = single_text_value(text, "Hash Algorithm")
    serial = single_text_value(text, "Serial number")
    gen_time_text = single_text_value(text, "Time stamp")
    accuracy_text = single_text_value(text, "Accuracy")
    ordering_text = single_text_value(text, "Ordering")
    nonce = single_text_value(text, "Nonce")
    if version != "1":
        raise TimestampError("RFC 3161 response version must be 1")
    if not safe_oid(policy_oid):
        raise TimestampError("RFC 3161 response policy OID is malformed")
    if hash_algorithm.lower() != HASH_ALGORITHM:
        raise TimestampError("RFC 3161 response must use SHA-256")
    if not re.fullmatch(r"0x[0-9A-Fa-f]{1,40}", serial):
        raise TimestampError("RFC 3161 serial number is malformed or exceeds 160 bits")
    if not re.fullmatch(r"0x[0-9A-Fa-f]{16,128}", nonce):
        raise TimestampError("RFC 3161 response must contain the request nonce")
    if ordering_text not in ("yes", "no"):
        raise TimestampError("RFC 3161 ordering flag is malformed")
    return {
        "policy_oid": policy_oid,
        "serial_hex": serial.lower(),
        "gen_time_unix_ms": parse_timestamp_ms(gen_time_text),
        "accuracy_micros": parse_accuracy_micros(accuracy_text),
        "ordering": ordering_text == "yes",
        "nonce": nonce.lower(),
    }


def write_bytes_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent.as_posix()
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def create_request(commitment_path: Path, policy_oid: str) -> bytes:
    if not safe_oid(policy_oid):
        raise TimestampError("timestamp policy OID is malformed")
    commitment_raw, _ = read_commitment(commitment_path)
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        commitment_snapshot = temporary / "commitment.json"
        request_snapshot = temporary / "request.tsq"
        write_bytes_atomic(commitment_snapshot, commitment_raw)
        request = run_openssl(
            [
                "ts",
                "-query",
                "-data",
                commitment_snapshot.as_posix(),
                "-sha256",
                "-tspolicy",
                policy_oid,
                "-cert",
            ]
        )
        if not 1 <= len(request) <= MAX_REQUEST_BYTES:
            raise TimestampError("OpenSSL returned an invalid RFC 3161 request size")
        write_bytes_atomic(request_snapshot, request)
        parsed = inspect_request(request_snapshot)
    if parsed["policy_oid"] != policy_oid:
        raise TimestampError("generated RFC 3161 request policy does not match")
    return request


def signer_identity(response_path: Path, untrusted_chain_path: Path | None) -> dict:
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        token_path = temporary / "timestamp-token.der"
        signer_path = temporary / "timestamp-signer.pem"
        token = run_openssl(
            ["ts", "-reply", "-in", response_path.as_posix(), "-token_out"]
        )
        write_bytes_atomic(token_path, token)
        arguments = [
            "cms",
            "-verify",
            "-inform",
            "DER",
            "-in",
            token_path.as_posix(),
            "-noverify",
            "-binary",
            "-signer",
            signer_path.as_posix(),
            "-out",
            os.devnull,
        ]
        if untrusted_chain_path is not None:
            arguments.extend(["-certfile", untrusted_chain_path.as_posix()])
        run_openssl(arguments)
        signer_pem = crypto_support.read_bounded(
            signer_path, MAX_SIGNER_CERTIFICATE_BYTES, "RFC 3161 signer certificate"
        )
        if signer_pem.count(b"-----BEGIN CERTIFICATE-----") != 1:
            raise TimestampError("RFC 3161 token must have exactly one signer")
        signer_der = run_openssl(
            ["x509", "-in", signer_path.as_posix(), "-outform", "DER"]
        )
        public_key_pem = run_openssl(
            ["x509", "-in", signer_path.as_posix(), "-pubkey", "-noout"]
        )
        public_key_der = run_openssl(
            ["pkey", "-pubin", "-outform", "DER"], input_bytes=public_key_pem
        )
    return {
        "certificate_sha256": sha256(signer_der).hexdigest(),
        "spki_sha256": sha256(public_key_der).hexdigest(),
    }


def verification_arguments(
    binding_option: str,
    binding_path: Path,
    response_path: Path,
    ca_file_path: Path,
    untrusted_chain_path: Path | None,
    gen_time_unix_ms: int,
) -> list[str]:
    arguments = [
        "ts",
        "-verify",
        binding_option,
        binding_path.as_posix(),
        "-in",
        response_path.as_posix(),
        "-CAfile",
        ca_file_path.as_posix(),
    ]
    if untrusted_chain_path is not None:
        arguments.extend(["-untrusted", untrusted_chain_path.as_posix()])
    arguments.extend(
        [
            "-purpose",
            "timestampsign",
            "-attime",
            str(gen_time_unix_ms // 1000),
            "-x509_strict",
            "-check_ss_sig",
            "-auth_level",
            "2",
            "-verify_depth",
            "5",
        ]
    )
    return arguments


def verify_timestamp(
    commitment_path: Path,
    request_path: Path,
    response_path: Path,
    ca_file_path: Path,
    untrusted_chain_path: Path | None,
    expected_policy_oid: str,
    expected_tsa_spki_sha256: str,
) -> dict:
    if not safe_oid(expected_policy_oid):
        raise TimestampError("expected timestamp policy OID is malformed")
    if not lowercase_sha256(expected_tsa_spki_sha256):
        raise TimestampError("expected TSA SPKI SHA-256 is malformed")
    commitment_raw, commitment = read_commitment(commitment_path)
    request_raw = crypto_support.read_bounded(
        request_path, MAX_REQUEST_BYTES, "RFC 3161 request"
    )
    response_raw = crypto_support.read_bounded(
        response_path, MAX_RESPONSE_BYTES, "RFC 3161 response"
    )
    ca_bundle = crypto_support.read_bounded(
        ca_file_path, MAX_CA_BUNDLE_BYTES, "RFC 3161 trust-anchor bundle"
    )
    untrusted_chain = (
        crypto_support.read_bounded(
            untrusted_chain_path,
            MAX_UNTRUSTED_CHAIN_BYTES,
            "RFC 3161 untrusted certificate chain",
        )
        if untrusted_chain_path is not None
        else None
    )
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        commitment_snapshot = temporary / "commitment.json"
        request_snapshot = temporary / "request.tsq"
        response_snapshot = temporary / "response.tsr"
        ca_snapshot = temporary / "trust-anchors.pem"
        chain_snapshot = (
            temporary / "untrusted-chain.pem"
            if untrusted_chain is not None
            else None
        )
        for snapshot, contents in (
            (commitment_snapshot, commitment_raw),
            (request_snapshot, request_raw),
            (response_snapshot, response_raw),
            (ca_snapshot, ca_bundle),
        ):
            write_bytes_atomic(snapshot, contents)
        if chain_snapshot is not None and untrusted_chain is not None:
            write_bytes_atomic(chain_snapshot, untrusted_chain)

        request = inspect_request(request_snapshot)
        response = inspect_response(response_snapshot)
        if request["policy_oid"] != expected_policy_oid:
            raise TimestampError("RFC 3161 request policy is not the expected policy")
        if response["policy_oid"] != expected_policy_oid:
            raise TimestampError("RFC 3161 response policy is not the expected policy")
        if response["nonce"] != request["nonce"].lower():
            raise TimestampError("RFC 3161 response nonce does not match the request")

        now_ms = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
        gen_time_ms = response["gen_time_unix_ms"]
        accuracy_micros = response["accuracy_micros"]
        if accuracy_micros is None:
            raise TimestampError("RFC 3161 response must declare timestamp accuracy")
        if accuracy_micros > MAX_TIMESTAMP_ACCURACY_MICROS:
            raise TimestampError("RFC 3161 timestamp accuracy exceeds five minutes")
        if gen_time_ms > now_ms + MAX_FUTURE_SKEW_MS:
            raise TimestampError("RFC 3161 genTime is implausibly in the future")
        if gen_time_ms + MAX_DECLARED_CLOCK_SKEW_MS < commitment["registered_at_ms"]:
            raise TimestampError(
                "RFC 3161 genTime precedes the declared registration time beyond clock skew"
            )

        run_openssl(
            verification_arguments(
                "-queryfile",
                request_snapshot,
                response_snapshot,
                ca_snapshot,
                chain_snapshot,
                gen_time_ms,
            )
        )
        run_openssl(
            verification_arguments(
                "-data",
                commitment_snapshot,
                response_snapshot,
                ca_snapshot,
                chain_snapshot,
                gen_time_ms,
            )
        )
        signer = signer_identity(response_snapshot, chain_snapshot)
    if not hmac.compare_digest(signer["spki_sha256"], expected_tsa_spki_sha256):
        raise TimestampError("RFC 3161 signer does not match the expected TSA SPKI")

    canonical_commitment = study_support.canonical_commitment(commitment)
    openssl_version = run_openssl(["version"]).decode("utf-8", errors="strict").strip()
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": "pass",
        "timestamp_protocol": TIMESTAMP_PROTOCOL,
        "trusted_timestamp_assurance": TRUSTED_TIMESTAMP_ASSURANCE,
        "message_imprint_algorithm": HASH_ALGORITHM,
        "policy_oid": expected_policy_oid,
        "serial_hex": response["serial_hex"],
        "gen_time_unix_ms": gen_time_ms,
        "accuracy_micros": accuracy_micros,
        "latest_trusted_time_unix_ms": gen_time_ms
        + (accuracy_micros + 999) // 1000,
        "ordering": response["ordering"],
        "request_nonce_present": True,
        "study_id": commitment["study_id"],
        "registered_at_ms": commitment["registered_at_ms"],
        "corpus_class": commitment["corpus_class"],
        "commitment_file_sha256": sha256(commitment_raw).hexdigest(),
        "commitment_canonical_sha256": sha256(canonical_commitment).hexdigest(),
        "preregistration_canonical_sha256": commitment[
            "preregistration_canonical_sha256"
        ],
        "corpus_sha256": commitment["corpus_sha256"],
        "packet_canonical_sha256": commitment["packet_canonical_sha256"],
        "request_sha256": sha256(request_raw).hexdigest(),
        "response_sha256": sha256(response_raw).hexdigest(),
        "tsa_signer_certificate_sha256": signer["certificate_sha256"],
        "tsa_signer_spki_sha256": signer["spki_sha256"],
        "trust_anchor_bundle_sha256": sha256(ca_bundle).hexdigest(),
        "untrusted_chain_sha256": (
            sha256(untrusted_chain).hexdigest() if untrusted_chain is not None else None
        ),
        "certificate_validation_time_basis": "tsa_gen_time",
        "revocation_assurance": "not_checked",
        "verification_time_unix_ms": now_ms,
        "verification_tool": openssl_version,
    }


def main() -> int:
    args = parse_args()
    try:
        if args.command == "request":
            output = Path(args.output)
            crypto_support.ensure_distinct_output(output, [Path(args.commitment)])
            request = create_request(Path(args.commitment), args.policy_oid)
            write_bytes_atomic(output, request)
            print(f"RFC 3161 timestamp request written to {output}")
            return 0

        output = Path(args.output) if args.output else None
        if output is not None:
            protected = [
                Path(args.commitment),
                Path(args.request),
                Path(args.response),
                Path(args.ca_file),
            ]
            if args.untrusted_chain:
                protected.append(Path(args.untrusted_chain))
            crypto_support.ensure_distinct_output(output, protected)
        report = verify_timestamp(
            Path(args.commitment),
            Path(args.request),
            Path(args.response),
            Path(args.ca_file),
            Path(args.untrusted_chain) if args.untrusted_chain else None,
            args.expected_policy_oid,
            args.expected_tsa_spki_sha256,
        )
        if output is not None:
            crypto_support.write_json_atomic(output, report)
            print(f"RFC 3161 verification written to {output} (status=pass)")
        else:
            import json

            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (TimestampError, UnicodeDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1 if getattr(args, "require_pass", False) else 2


if __name__ == "__main__":
    sys.exit(main())
