#!/usr/bin/env python3

import argparse
import base64
import binascii
import hmac
import json
import os
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path


SCHEMA_VERSION = "aura.evidence_manifest_attestation.v1"
VERIFICATION_SCHEMA_VERSION = "aura.evidence_manifest_attestation_verification.v1"
SIGNATURE_ALGORITHM = "Ed25519"
SIGNED_PAYLOAD_DOMAIN = b"aura.evidence-manifest.attestation.v1\x00"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ATTESTATION_BYTES = 64 * 1024
ATTESTATION_FIELDS = {
    "schema_version",
    "signature_algorithm",
    "key_id",
    "manifest_sha256",
    "public_key_spki_sha256",
    "signature_base64",
}


class AttestationError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sign or verify a detached Ed25519 AURA evidence-manifest attestation."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign_parser = subparsers.add_parser("sign", help="Create a detached attestation.")
    sign_parser.add_argument("--manifest", required=True)
    sign_parser.add_argument("--private-key", required=True)
    sign_parser.add_argument("--key-id", required=True)
    sign_parser.add_argument("--output", required=True)

    verify_parser = subparsers.add_parser("verify", help="Verify a detached attestation.")
    verify_parser.add_argument("--manifest", required=True)
    verify_parser.add_argument("--attestation", required=True)
    verify_parser.add_argument("--public-key", required=True)
    verify_parser.add_argument("--expected-key-id", default=None)
    verify_parser.add_argument("--output", default=None)
    verify_parser.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def read_bounded(path: Path, maximum: int, label: str) -> bytes:
    if not path.is_file():
        raise AttestationError(f"{label} is missing or not a regular file: {path}")
    size = path.stat().st_size
    if size <= 0 or size > maximum:
        raise AttestationError(f"{label} size must be within 1..={maximum} bytes")
    return path.read_bytes()


def safe_key_id(key_id: str) -> bool:
    return key_id.isascii() and 1 <= len(key_id) <= 64 and all(
        byte.isalnum() or byte in "_.-" for byte in key_id
    )


def validate_release_manifest(manifest: bytes) -> dict:
    try:
        payload = json.loads(manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AttestationError(f"evidence manifest is invalid JSON: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != "aura.evidence_manifest.v1":
        raise AttestationError("evidence manifest schema_version is unsupported")
    if payload.get("evidence_status") != "pass":
        raise AttestationError("only a passing evidence manifest may be attested")
    return payload


def run_openssl(arguments: list[str], input_bytes: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *arguments],
            input=input_bytes,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as error:
        raise AttestationError("OpenSSL is required for Ed25519 attestation") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise AttestationError(f"OpenSSL command failed: {detail or 'unknown error'}")
    return result.stdout


def public_key_der_from_private(private_key: Path) -> bytes:
    return run_openssl(
        ["pkey", "-in", private_key.as_posix(), "-pubout", "-outform", "DER"]
    )


def public_key_der_from_public(public_key: Path) -> bytes:
    return run_openssl(
        ["pkey", "-pubin", "-in", public_key.as_posix(), "-outform", "DER"]
    )


def canonical_claims(attestation: dict) -> bytes:
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


def write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent.as_posix()
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def ensure_distinct_output(output: Path, protected_paths: list[Path]) -> None:
    resolved_output = output.resolve()
    if any(resolved_output == protected.resolve() for protected in protected_paths):
        raise AttestationError("output path must not overwrite an attestation input")


def sign_manifest(
    manifest_path: Path,
    private_key_path: Path,
    key_id: str,
) -> dict:
    if not safe_key_id(key_id):
        raise AttestationError(
            "key_id must be 1..64 ASCII alphanumeric, '_', '-', or '.' characters"
        )
    manifest = read_bounded(manifest_path, MAX_MANIFEST_BYTES, "evidence manifest")
    validate_release_manifest(manifest)
    read_bounded(private_key_path, MAX_ATTESTATION_BYTES, "Ed25519 private key")
    if os.name != "nt" and (private_key_path.stat().st_mode & 0o077) != 0:
        raise AttestationError("Ed25519 private key permissions must not allow group or world access")
    public_key_der = public_key_der_from_private(private_key_path)
    attestation = {
        "schema_version": SCHEMA_VERSION,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "manifest_sha256": sha256(manifest).hexdigest(),
        "public_key_spki_sha256": sha256(public_key_der).hexdigest(),
    }
    with tempfile.NamedTemporaryFile() as claims_file:
        claims_file.write(canonical_claims(attestation))
        claims_file.flush()
        signature = run_openssl(
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
    raw = read_bounded(path, MAX_ATTESTATION_BYTES, "evidence attestation")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AttestationError(f"evidence attestation is invalid JSON: {error}") from error
    if not isinstance(payload, dict) or set(payload) != ATTESTATION_FIELDS:
        raise AttestationError("evidence attestation fields do not match the v1 schema")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise AttestationError("evidence attestation schema_version is unsupported")
    if payload.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        raise AttestationError("evidence attestation signature algorithm is unsupported")
    if not safe_key_id(payload.get("key_id", "")):
        raise AttestationError("evidence attestation key_id is invalid")
    for field in ("manifest_sha256", "public_key_spki_sha256"):
        value = payload.get(field)
        if not isinstance(value, str) or len(value) != 64:
            raise AttestationError(f"evidence attestation {field} is malformed")
        try:
            bytes.fromhex(value)
        except ValueError as error:
            raise AttestationError(
                f"evidence attestation {field} is malformed"
            ) from error
    try:
        signature = base64.b64decode(payload["signature_base64"], validate=True)
    except (binascii.Error, ValueError) as error:
        raise AttestationError("evidence attestation signature is malformed") from error
    if len(signature) != 64:
        raise AttestationError("evidence attestation signature is malformed")
    return payload


def verify_manifest(
    manifest_path: Path,
    attestation_path: Path,
    public_key_path: Path,
    expected_key_id: str | None = None,
) -> dict:
    manifest = read_bounded(manifest_path, MAX_MANIFEST_BYTES, "evidence manifest")
    manifest_payload = validate_release_manifest(manifest)
    read_bounded(public_key_path, MAX_ATTESTATION_BYTES, "Ed25519 public key")
    attestation = load_attestation(attestation_path)
    if expected_key_id is not None and not hmac.compare_digest(
        attestation["key_id"], expected_key_id
    ):
        raise AttestationError("evidence attestation key_id is not trusted")
    manifest_digest = sha256(manifest).hexdigest()
    if not hmac.compare_digest(attestation["manifest_sha256"], manifest_digest):
        raise AttestationError("evidence manifest digest does not match its attestation")
    public_key_digest = sha256(public_key_der_from_public(public_key_path)).hexdigest()
    if not hmac.compare_digest(
        attestation["public_key_spki_sha256"], public_key_digest
    ):
        raise AttestationError("trusted public key does not match the attestation")

    signature = base64.b64decode(attestation["signature_base64"], validate=True)
    with (
        tempfile.NamedTemporaryFile() as signature_file,
        tempfile.NamedTemporaryFile() as claims_file,
    ):
        signature_file.write(signature)
        signature_file.flush()
        claims_file.write(canonical_claims(attestation))
        claims_file.flush()
        run_openssl(
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
            ],
        )
    return {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": "pass",
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": attestation["key_id"],
        "manifest_sha256": manifest_digest,
        "manifest_evidence_status": manifest_payload["evidence_status"],
        "public_key_spki_sha256": public_key_digest,
    }


def main() -> int:
    args = parse_args()
    try:
        if args.command == "sign":
            output = Path(args.output)
            ensure_distinct_output(
                output,
                [Path(args.manifest), Path(args.private_key)],
            )
            attestation = sign_manifest(
                Path(args.manifest), Path(args.private_key), args.key_id
            )
            write_json_atomic(output, attestation)
            print(f"evidence attestation written to {output}")
            return 0

        report = verify_manifest(
            Path(args.manifest),
            Path(args.attestation),
            Path(args.public_key),
            args.expected_key_id,
        )
        if args.output:
            output = Path(args.output)
            ensure_distinct_output(
                output,
                [Path(args.manifest), Path(args.attestation), Path(args.public_key)],
            )
            write_json_atomic(output, report)
            print(f"evidence attestation verification written to {args.output} (status=pass)")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except AttestationError as error:
        print(str(error), file=sys.stderr)
        return 1 if getattr(args, "require_pass", False) else 2


if __name__ == "__main__":
    sys.exit(main())
