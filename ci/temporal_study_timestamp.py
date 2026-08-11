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
    "aura.military.temporal_study_timestamp_verification.v2"
)
TIMESTAMP_PROTOCOL = "RFC3161"
HASH_ALGORITHM = "sha256"
TRUSTED_TIMESTAMP_ASSURANCE = "rfc3161_trusted_chain"
REVOCATION_ASSURANCE = "full_chain_crl_at_gen_time"
REVOCATION_EVIDENCE_KIND = "offline_complete_crl"
REVOCATION_CRL_FIELDS = {
    "issuer_name_sha256",
    "this_update_unix_ms",
    "next_update_unix_ms",
    "crl_number_hex",
    "der_sha256",
}
MAX_COMMITMENT_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_CA_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_UNTRUSTED_CHAIN_BYTES = 4 * 1024 * 1024
MAX_SIGNER_CERTIFICATE_BYTES = 256 * 1024
MAX_CRL_BYTES = 4 * 1024 * 1024
MAX_CRL_COUNT = 6
MAX_TOTAL_CRL_BYTES = 16 * 1024 * 1024
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
    verify_parser.add_argument(
        "--revocation-crl",
        action="append",
        required=True,
        help=(
            "PEM full CRL captured for one non-anchor certificate issuer; "
            "repeat for each issuer in the TSA chain."
        ),
    )
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


def create_request_for_document(document: bytes, policy_oid: str) -> bytes:
    if not safe_oid(policy_oid):
        raise TimestampError("timestamp policy OID is malformed")
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        document_snapshot = temporary / "timestamped-document.bin"
        request_snapshot = temporary / "request.tsq"
        write_bytes_atomic(document_snapshot, document)
        parsed = None
        request = b""
        for _ in range(8):
            request = run_openssl(
                [
                    "ts",
                    "-query",
                    "-data",
                    document_snapshot.as_posix(),
                    "-sha256",
                    "-tspolicy",
                    policy_oid,
                    "-cert",
                ]
            )
            if not 1 <= len(request) <= MAX_REQUEST_BYTES:
                raise TimestampError("OpenSSL returned an invalid RFC 3161 request size")
            write_bytes_atomic(request_snapshot, request)
            try:
                parsed = inspect_request(request_snapshot)
                break
            except TimestampError as error:
                if "large nonce" not in str(error):
                    raise
        if parsed is None:
            raise TimestampError("OpenSSL did not generate a sufficiently large RFC 3161 nonce")
    if parsed["policy_oid"] != policy_oid:
        raise TimestampError("generated RFC 3161 request policy does not match")
    return request


def create_request(commitment_path: Path, policy_oid: str) -> bytes:
    commitment_raw, _ = read_commitment(commitment_path)
    return create_request_for_document(commitment_raw, policy_oid)


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
        "certificate_pem": signer_pem,
    }


def parse_crl_time_ms(value: str, label: str) -> int:
    normalized = " ".join(value.split())
    for format_string in ("%b %d %H:%M:%S %Y GMT", "%Y%m%d%H%M%SZ"):
        try:
            parsed = datetime.strptime(normalized, format_string).replace(
                tzinfo=timezone.utc
            )
            return int(parsed.timestamp() * 1000)
        except ValueError:
            continue
    raise TimestampError(f"X.509 CRL {label} is not strict UTC text")


def inspect_complete_crl(path: Path, raw: bytes, gen_time_unix_ms: int) -> dict:
    stripped = raw.strip()
    if (
        stripped.count(b"-----BEGIN X509 CRL-----") != 1
        or stripped.count(b"-----END X509 CRL-----") != 1
        or not stripped.startswith(b"-----BEGIN X509 CRL-----\n")
        or not stripped.endswith(b"\n-----END X509 CRL-----")
    ):
        raise TimestampError("revocation evidence must contain exactly one PEM X.509 CRL")
    details = run_openssl(
        [
            "crl",
            "-in",
            path.as_posix(),
            "-noout",
            "-issuer",
            "-lastupdate",
            "-nextupdate",
            "-crlnumber",
            "-nameopt",
            "RFC2253",
        ]
    ).decode("utf-8", errors="strict")
    values = {}
    for label, prefix in (
        ("issuer", "issuer="),
        ("last_update", "lastUpdate="),
        ("next_update", "nextUpdate="),
        ("crl_number", "crlNumber="),
    ):
        matches = [
            line[len(prefix) :].strip()
            for line in details.splitlines()
            if line.startswith(prefix)
        ]
        if len(matches) != 1 or not matches[0] or matches[0] == "NONE":
            raise TimestampError(f"X.509 CRL has missing or duplicate {label}")
        values[label] = matches[0]
    if not re.fullmatch(r"0x[0-9A-Fa-f]{1,40}", values["crl_number"]):
        raise TimestampError("X.509 CRL number is malformed or exceeds 160 bits")
    text = run_openssl(
        ["crl", "-in", path.as_posix(), "-noout", "-text"]
    ).decode("utf-8", errors="strict")
    if "X509v3 Delta CRL Indicator:" in text:
        raise TimestampError("delta CRLs are not accepted as archival revocation evidence")
    if "X509v3 Issuing Distribution Point:" in text:
        raise TimestampError(
            "indirect or distribution-point-scoped CRLs are not accepted as archival evidence"
        )
    this_update_ms = parse_crl_time_ms(values["last_update"], "thisUpdate")
    next_update_ms = parse_crl_time_ms(values["next_update"], "nextUpdate")
    if this_update_ms > gen_time_unix_ms or next_update_ms < gen_time_unix_ms:
        raise TimestampError("X.509 CRL does not cover the RFC 3161 genTime")
    if next_update_ms <= this_update_ms:
        raise TimestampError("X.509 CRL validity interval is inconsistent")
    crl_der = run_openssl(
        ["crl", "-in", path.as_posix(), "-outform", "DER"]
    )
    return {
        "issuer": values["issuer"],
        "issuer_name_sha256": sha256(values["issuer"].encode("utf-8")).hexdigest(),
        "this_update_unix_ms": this_update_ms,
        "next_update_unix_ms": next_update_ms,
        "crl_number_hex": values["crl_number"].lower(),
        "der_sha256": sha256(crl_der).hexdigest(),
    }


def certificate_chain_subjects(
    signer_path: Path,
    ca_file_path: Path,
    untrusted_chain_path: Path | None,
    gen_time_unix_ms: int,
) -> list[str]:
    arguments = [
        "verify",
        "-show_chain",
        "-nameopt",
        "RFC2253",
        "-CAfile",
        ca_file_path.as_posix(),
        "-no-CApath",
        "-no-CAstore",
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
            signer_path.as_posix(),
        ]
    )
    output = run_openssl(arguments).decode("utf-8", errors="strict")
    subjects = {}
    for line in output.splitlines():
        match = re.fullmatch(r"depth=(\d+): (.+?)(?: \(untrusted\))?", line.strip())
        if match is not None:
            depth = int(match.group(1))
            if depth in subjects:
                raise TimestampError("OpenSSL returned a duplicate certificate-chain depth")
            subjects[depth] = match.group(2)
    if len(subjects) < 2 or sorted(subjects) != list(range(len(subjects))):
        raise TimestampError("OpenSSL did not return a complete TSA certificate chain")
    ordered = [subjects[depth] for depth in range(len(subjects))]
    if len(set(ordered[1:])) != len(ordered) - 1:
        raise TimestampError("TSA certificate-chain issuer names must be distinct")
    return ordered


def verify_historical_crls(
    signer_pem: bytes,
    ca_file_path: Path,
    untrusted_chain_path: Path | None,
    crl_paths: list[Path],
    gen_time_unix_ms: int,
    temporary: Path,
) -> dict:
    if not 1 <= len(crl_paths) <= MAX_CRL_COUNT:
        raise TimestampError(
            f"revocation evidence requires 1..={MAX_CRL_COUNT} complete CRLs"
        )
    resolved = [path.resolve() for path in crl_paths]
    if len(set(resolved)) != len(resolved):
        raise TimestampError("revocation evidence repeats a CRL path")
    crl_raw = [
        crypto_support.read_bounded(path, MAX_CRL_BYTES, "X.509 revocation CRL")
        for path in crl_paths
    ]
    if sum(len(raw) for raw in crl_raw) > MAX_TOTAL_CRL_BYTES:
        raise TimestampError("X.509 revocation CRL set is too large")

    signer_path = temporary / "timestamp-signer-for-revocation.pem"
    write_bytes_atomic(signer_path, signer_pem)
    crls = []
    for index, raw in enumerate(crl_raw):
        snapshot = temporary / f"revocation-{index:02d}.crl.pem"
        write_bytes_atomic(snapshot, raw)
        crls.append(inspect_complete_crl(snapshot, raw, gen_time_unix_ms))

    chain_subjects = certificate_chain_subjects(
        signer_path,
        ca_file_path,
        untrusted_chain_path,
        gen_time_unix_ms,
    )
    required_issuers = chain_subjects[1:]
    observed_issuers = [crl["issuer"] for crl in crls]
    if sorted(observed_issuers) != sorted(required_issuers):
        raise TimestampError(
            "complete CRLs must cover exactly every non-anchor certificate issuer"
        )

    combined_path = temporary / "revocation-crls.pem"
    write_bytes_atomic(
        combined_path,
        b"\n".join(raw.strip() for raw in crl_raw) + b"\n",
    )
    arguments = [
        "verify",
        "-CAfile",
        ca_file_path.as_posix(),
        "-no-CApath",
        "-no-CAstore",
    ]
    if untrusted_chain_path is not None:
        arguments.extend(["-untrusted", untrusted_chain_path.as_posix()])
    arguments.extend(
        [
            "-CRLfile",
            combined_path.as_posix(),
            "-crl_check_all",
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
            signer_path.as_posix(),
        ]
    )
    run_openssl(arguments)

    exported = sorted(
        (
            {
                key: crl[key]
                for key in (
                    "issuer_name_sha256",
                    "this_update_unix_ms",
                    "next_update_unix_ms",
                    "crl_number_hex",
                    "der_sha256",
                )
            }
            for crl in crls
        ),
        key=lambda crl: crl["der_sha256"],
    )
    der_digests = [crl["der_sha256"] for crl in exported]
    return {
        "revocation_assurance": REVOCATION_ASSURANCE,
        "revocation_evidence_kind": REVOCATION_EVIDENCE_KIND,
        "revocation_validation_time_basis": "tsa_gen_time",
        "revocation_scope": "full_non_anchor_chain",
        "revocation_network_fetch_used": False,
        "revocation_delta_crls_used": False,
        "revocation_indirect_crls_used": False,
        "revocation_checked_certificate_count": len(required_issuers),
        "revocation_crl_count": len(exported),
        "revocation_crl_der_sha256s": der_digests,
        "revocation_crl_set_sha256": sha256(
            "\n".join(der_digests).encode("ascii")
        ).hexdigest(),
        "revocation_crls": exported,
    }


def validate_revocation_claims(payload: dict) -> None:
    if (
        payload.get("revocation_assurance") != REVOCATION_ASSURANCE
        or payload.get("revocation_evidence_kind") != REVOCATION_EVIDENCE_KIND
        or payload.get("revocation_validation_time_basis") != "tsa_gen_time"
        or payload.get("revocation_scope") != "full_non_anchor_chain"
        or payload.get("revocation_network_fetch_used") is not False
        or payload.get("revocation_delta_crls_used") is not False
        or payload.get("revocation_indirect_crls_used") is not False
    ):
        raise TimestampError("RFC 3161 revocation assurance claims are invalid")
    gen_time = payload.get("gen_time_unix_ms")
    checked_count = payload.get("revocation_checked_certificate_count")
    crl_count = payload.get("revocation_crl_count")
    if (
        isinstance(gen_time, bool)
        or not isinstance(gen_time, int)
        or gen_time <= 0
        or isinstance(checked_count, bool)
        or not isinstance(checked_count, int)
        or checked_count <= 0
        or isinstance(crl_count, bool)
        or not isinstance(crl_count, int)
        or crl_count > MAX_CRL_COUNT
        or crl_count != checked_count
    ):
        raise TimestampError("RFC 3161 revocation evidence counts are invalid")
    crls = payload.get("revocation_crls")
    digests = payload.get("revocation_crl_der_sha256s")
    if (
        not isinstance(crls, list)
        or len(crls) != crl_count
        or not isinstance(digests, list)
        or len(digests) != crl_count
        or digests != sorted(set(digests))
        or any(not lowercase_sha256(digest) for digest in digests)
    ):
        raise TimestampError("RFC 3161 revocation CRL identities are invalid")
    issuer_digests = set()
    observed_digests = []
    for crl in crls:
        if not isinstance(crl, dict) or set(crl) != REVOCATION_CRL_FIELDS:
            raise TimestampError("RFC 3161 revocation CRL claims are invalid")
        issuer_digest = crl.get("issuer_name_sha256")
        der_digest = crl.get("der_sha256")
        this_update = crl.get("this_update_unix_ms")
        next_update = crl.get("next_update_unix_ms")
        number = crl.get("crl_number_hex")
        if (
            not lowercase_sha256(issuer_digest)
            or issuer_digest in issuer_digests
            or not lowercase_sha256(der_digest)
            or isinstance(this_update, bool)
            or not isinstance(this_update, int)
            or isinstance(next_update, bool)
            or not isinstance(next_update, int)
            or not this_update <= gen_time <= next_update
            or next_update <= this_update
            or not isinstance(number, str)
            or re.fullmatch(r"0x[0-9a-f]{1,40}", number) is None
        ):
            raise TimestampError("RFC 3161 revocation CRL claims are inconsistent")
        issuer_digests.add(issuer_digest)
        observed_digests.append(der_digest)
    set_digest = payload.get("revocation_crl_set_sha256")
    if (
        observed_digests != digests
        or not lowercase_sha256(set_digest)
        or not hmac.compare_digest(
            set_digest,
            sha256("\n".join(digests).encode("ascii")).hexdigest(),
        )
    ):
        raise TimestampError("RFC 3161 revocation CRL set digest is inconsistent")


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


def verify_document_timestamp(
    document: bytes,
    request_path: Path,
    response_path: Path,
    ca_file_path: Path,
    untrusted_chain_path: Path | None,
    expected_policy_oid: str,
    expected_tsa_spki_sha256: str,
    revocation_crl_paths: list[Path],
) -> dict:
    if not safe_oid(expected_policy_oid):
        raise TimestampError("expected timestamp policy OID is malformed")
    if not lowercase_sha256(expected_tsa_spki_sha256):
        raise TimestampError("expected TSA SPKI SHA-256 is malformed")
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
        document_snapshot = temporary / "timestamped-document.bin"
        request_snapshot = temporary / "request.tsq"
        response_snapshot = temporary / "response.tsr"
        ca_snapshot = temporary / "trust-anchors.pem"
        chain_snapshot = (
            temporary / "untrusted-chain.pem"
            if untrusted_chain is not None
            else None
        )
        for snapshot, contents in (
            (document_snapshot, document),
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
                document_snapshot,
                response_snapshot,
                ca_snapshot,
                chain_snapshot,
                gen_time_ms,
            )
        )
        signer = signer_identity(response_snapshot, chain_snapshot)
        revocation = verify_historical_crls(
            signer["certificate_pem"],
            ca_snapshot,
            chain_snapshot,
            revocation_crl_paths,
            gen_time_ms,
            temporary,
        )
    if not hmac.compare_digest(signer["spki_sha256"], expected_tsa_spki_sha256):
        raise TimestampError("RFC 3161 signer does not match the expected TSA SPKI")

    openssl_version = run_openssl(["version"]).decode("utf-8", errors="strict").strip()
    accuracy_ms = (accuracy_micros + 999) // 1000
    return {
        "timestamp_protocol": TIMESTAMP_PROTOCOL,
        "trusted_timestamp_assurance": TRUSTED_TIMESTAMP_ASSURANCE,
        "message_imprint_algorithm": HASH_ALGORITHM,
        "policy_oid": expected_policy_oid,
        "serial_hex": response["serial_hex"],
        "gen_time_unix_ms": gen_time_ms,
        "accuracy_micros": accuracy_micros,
        "earliest_trusted_time_unix_ms": max(0, gen_time_ms - accuracy_ms),
        "latest_trusted_time_unix_ms": gen_time_ms + accuracy_ms,
        "ordering": response["ordering"],
        "request_nonce_present": True,
        "timestamped_document_sha256": sha256(document).hexdigest(),
        "request_sha256": sha256(request_raw).hexdigest(),
        "response_sha256": sha256(response_raw).hexdigest(),
        "tsa_signer_certificate_sha256": signer["certificate_sha256"],
        "tsa_signer_spki_sha256": signer["spki_sha256"],
        "trust_anchor_bundle_sha256": sha256(ca_bundle).hexdigest(),
        "untrusted_chain_sha256": (
            sha256(untrusted_chain).hexdigest() if untrusted_chain is not None else None
        ),
        "certificate_validation_time_basis": "tsa_gen_time",
        **revocation,
        "verification_time_unix_ms": now_ms,
        "verification_tool": openssl_version,
    }


def verify_timestamp(
    commitment_path: Path,
    request_path: Path,
    response_path: Path,
    ca_file_path: Path,
    untrusted_chain_path: Path | None,
    expected_policy_oid: str,
    expected_tsa_spki_sha256: str,
    revocation_crl_paths: list[Path],
) -> dict:
    commitment_raw, commitment = read_commitment(commitment_path)
    timestamp = verify_document_timestamp(
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
        < commitment["registered_at_ms"]
    ):
        raise TimestampError(
            "RFC 3161 genTime precedes the declared registration time beyond clock skew"
        )
    commitment_file_sha256 = timestamp.pop("timestamped_document_sha256")
    canonical_commitment = study_support.canonical_commitment(commitment)
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": "pass",
        **timestamp,
        "study_id": commitment["study_id"],
        "registered_at_ms": commitment["registered_at_ms"],
        "corpus_class": commitment["corpus_class"],
        "commitment_file_sha256": commitment_file_sha256,
        "commitment_canonical_sha256": sha256(canonical_commitment).hexdigest(),
        "preregistration_canonical_sha256": commitment[
            "preregistration_canonical_sha256"
        ],
        "corpus_sha256": commitment["corpus_sha256"],
        "packet_canonical_sha256": commitment["packet_canonical_sha256"],
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
            protected.extend(Path(path) for path in args.revocation_crl)
            crypto_support.ensure_distinct_output(output, protected)
        report = verify_timestamp(
            Path(args.commitment),
            Path(args.request),
            Path(args.response),
            Path(args.ca_file),
            Path(args.untrusted_chain) if args.untrusted_chain else None,
            args.expected_policy_oid,
            args.expected_tsa_spki_sha256,
            [Path(path) for path in args.revocation_crl],
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
