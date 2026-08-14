#!/usr/bin/env python3

import argparse
import base64
import binascii
import hmac
import json
import math
import os
import secrets
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
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


def _write_private_snapshot(path: Path, payload: bytes) -> None:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor is not None:
            os.close(descriptor)


@contextmanager
def private_key_snapshot(payload: bytes):
    """Expose already validated key bytes through a private immutable snapshot."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "private-key.pem"
        _write_private_snapshot(path, payload)
        yield path


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


def _read_bounded(
    path: Path,
    maximum: int,
    label: str,
    *,
    require_private_permissions: bool,
) -> tuple[bytes, tuple[int, int]]:
    if maximum <= 0:
        raise AttestationError(f"{label} byte bound must be positive")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except (FileNotFoundError, IsADirectoryError, OSError) as error:
        raise AttestationError(
            f"{label} is missing, is a symbolic link, or is not a regular file: {path}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AttestationError(f"{label} is not a regular file: {path}")
        if (
            require_private_permissions
            and os.name != "nt"
            and (metadata.st_mode & 0o077) != 0
        ):
            raise AttestationError(
                f"{label} permissions must not allow group or world access"
            )
        if metadata.st_size <= 0 or metadata.st_size > maximum:
            raise AttestationError(f"{label} size must be within 1..={maximum} bytes")
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if not raw or len(raw) > maximum:
            raise AttestationError(f"{label} size must be within 1..={maximum} bytes")
        final_metadata = os.fstat(descriptor)
        identity_before = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        identity_after = (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
            final_metadata.st_ctime_ns,
        )
        if len(raw) != metadata.st_size or identity_before != identity_after:
            raise AttestationError(f"{label} changed while it was being read")
        return raw, (metadata.st_dev, metadata.st_ino)
    finally:
        os.close(descriptor)


def read_bounded(path: Path, maximum: int, label: str) -> bytes:
    return read_bounded_with_identity(path, maximum, label)[0]


def read_bounded_with_identity(
    path: Path, maximum: int, label: str
) -> tuple[bytes, tuple[int, int]]:
    return _read_bounded(
        path,
        maximum,
        label,
        require_private_permissions=False,
    )


def read_bounded_private(path: Path, maximum: int, label: str) -> bytes:
    return read_bounded_private_with_identity(path, maximum, label)[0]


def read_bounded_private_with_identity(
    path: Path, maximum: int, label: str
) -> tuple[bytes, tuple[int, int]]:
    return _read_bounded(
        path,
        maximum,
        label,
        require_private_permissions=True,
    )


def safe_key_id(key_id: str) -> bool:
    return key_id.isascii() and 1 <= len(key_id) <= 64 and all(
        byte.isalnum() or byte in "_.-" for byte in key_id
    )


def validate_release_manifest(manifest: bytes) -> dict:
    try:
        payload = strict_json_loads(manifest)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
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
    if path.name in ("", ".", ".."):
        raise AttestationError("output path must name a file")
    try:
        serialized = (
            json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise AttestationError("output payload is not finite JSON") from error

    path.parent.mkdir(parents=True, exist_ok=True)
    parent_path = Path(os.path.abspath(path.parent))
    try:
        parent_before = os.lstat(parent_path)
    except OSError as error:
        raise AttestationError("output parent is inaccessible") from error
    if stat.S_ISLNK(parent_before.st_mode) or not stat.S_ISDIR(
        parent_before.st_mode
    ):
        raise AttestationError("output parent must be a real directory")

    directory_flags = os.O_RDONLY
    for name in ("O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW"):
        directory_flags |= getattr(os, name, 0)
    try:
        directory_descriptor = os.open(parent_path, directory_flags)
    except OSError as error:
        raise AttestationError("output parent cannot be opened safely") from error

    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None

    def assert_parent_bound() -> None:
        opened = os.fstat(directory_descriptor)
        try:
            observed = os.lstat(parent_path)
        except OSError as error:
            raise AttestationError("output parent changed during publication") from error
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or (observed.st_dev, observed.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise AttestationError("output parent changed during publication")

    def verify_descriptor(label: str) -> None:
        if descriptor is None:
            raise AttestationError(f"{label} is not open")
        os.lseek(descriptor, 0, os.SEEK_SET)
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, len(serialized) - observed + 1),
            )
            if not chunk:
                break
            observed += len(chunk)
            if observed > len(serialized):
                raise AttestationError(f"{label} exceeds its expected bytes")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or observed != len(serialized)
            or b"".join(chunks) != serialized
            or (
                before.st_dev,
                before.st_ino,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise AttestationError(f"{label} changed during verification")

    def assert_published_name() -> None:
        if descriptor is None:
            raise AttestationError("published output is not open")
        try:
            observed = os.stat(
                path.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise AttestationError("published output name is inaccessible") from error
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
            or (observed.st_dev, observed.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise AttestationError("published output was replaced during publication")

    try:
        try:
            opened_parent = os.fstat(directory_descriptor)
            if (opened_parent.st_dev, opened_parent.st_ino) != (
                parent_before.st_dev,
                parent_before.st_ino,
            ):
                raise AttestationError("output parent changed while opening")
            try:
                existing = os.stat(
                    path.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(
                    existing.st_mode
                ):
                    raise AttestationError(
                        "output target must be a regular non-symlink file"
                    )
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            for name in ("O_CLOEXEC", "O_NOFOLLOW"):
                flags |= getattr(os, name, 0)
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
            offset = 0
            while offset < len(serialized):
                written = os.write(descriptor, serialized[offset:])
                if written <= 0:
                    raise AttestationError("output write made no progress")
                offset += written
            os.fsync(descriptor)
            verify_descriptor("staged JSON output")
            assert_parent_bound()
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            assert_published_name()
            verify_descriptor("published JSON output")
            os.fsync(directory_descriptor)
            assert_parent_bound()
            assert_published_name()
        except AttestationError:
            raise
        except OSError as error:
            raise AttestationError("JSON output could not be published safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        # Never unlink a random staging name after an error; a concurrent
        # writer may have replaced it between failure and cleanup.
        os.close(directory_descriptor)


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
    private_key = read_bounded_private(
        private_key_path, MAX_ATTESTATION_BYTES, "Ed25519 private key"
    )
    with private_key_snapshot(private_key) as snapshot:
        public_key_der = public_key_der_from_private(snapshot)
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
                    snapshot.as_posix(),
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
        payload = strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise AttestationError(f"evidence attestation is invalid JSON: {error}") from error
    if not isinstance(payload, dict) or set(payload) != ATTESTATION_FIELDS:
        raise AttestationError("evidence attestation fields do not match the v1 schema")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise AttestationError("evidence attestation schema_version is unsupported")
    if payload.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        raise AttestationError("evidence attestation signature algorithm is unsupported")
    key_id = payload.get("key_id")
    if not isinstance(key_id, str) or not safe_key_id(key_id):
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
    signature_base64 = payload.get("signature_base64")
    if not isinstance(signature_base64, str):
        raise AttestationError("evidence attestation signature is malformed")
    try:
        signature = base64.b64decode(signature_base64, validate=True)
    except (binascii.Error, TypeError, ValueError) as error:
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
    if expected_key_id is not None and (
        not isinstance(expected_key_id, str) or not safe_key_id(expected_key_id)
    ):
        raise AttestationError("expected evidence key_id is invalid")
    manifest = read_bounded(manifest_path, MAX_MANIFEST_BYTES, "evidence manifest")
    manifest_payload = validate_release_manifest(manifest)
    public_key = read_bounded(
        public_key_path, MAX_ATTESTATION_BYTES, "Ed25519 public key"
    )
    attestation = load_attestation(attestation_path)
    if expected_key_id is not None and not hmac.compare_digest(
        attestation["key_id"], expected_key_id
    ):
        raise AttestationError("evidence attestation key_id is not trusted")
    manifest_digest = sha256(manifest).hexdigest()
    if not hmac.compare_digest(attestation["manifest_sha256"], manifest_digest):
        raise AttestationError("evidence manifest digest does not match its attestation")
    with private_key_snapshot(public_key) as public_key_snapshot:
        public_key_digest = sha256(
            public_key_der_from_public(public_key_snapshot)
        ).hexdigest()
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
                    public_key_snapshot.as_posix(),
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
