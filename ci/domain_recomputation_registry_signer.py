#!/usr/bin/env python3

"""Sign exact compact append-only recomputation-registry claims.

The signer treats registry entries and checkpoints as opaque, bounded, strict
compact JSON objects and never reserializes them.  The caller must supply the
exact bytes emitted by the corresponding typed Rust structure.  A closed
``kind`` allowlist selects a role-specific domain separator so an entry,
operator checkpoint signature, or witness checkpoint signature cannot be
replayed in another role.
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from ci import domain_result_timestamp_adapter as adapter_support
    from ci import evidence_attestation as crypto_support
    from ci import temporal_study_attestation as attestation_support
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import domain_result_timestamp_adapter as adapter_support
    import evidence_attestation as crypto_support
    import temporal_study_attestation as attestation_support


MAX_CLAIMS_BYTES = 2 * 1024 * 1024
SIGNING_DOMAINS = {
    "registry_entry": (b"aura.domain.recomputation-attempt-registry-entry.v1\x00"),
    "registry_checkpoint_operator": (
        b"aura.domain.recomputation-attempt-registry-checkpoint-operator.v1\x00"
    ),
    "registry_checkpoint_witness": (
        b"aura.domain.recomputation-attempt-registry-checkpoint-witness.v1\x00"
    ),
}

SignerError = adapter_support.AdapterError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Sign exact compact AURA append-only recomputation-registry claims "
            "with a role-separated Ed25519 domain."
        )
    )
    parser.add_argument("--claims", required=True)
    parser.add_argument("--kind", choices=tuple(SIGNING_DOMAINS), required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def _json_string(value: str) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def validate_claims_bytes(raw: bytes) -> bytes:
    """Validate strict compact JSON while preserving every claims byte."""

    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_CLAIMS_BYTES:
        raise SignerError(
            "recomputation registry claims size must be within "
            f"1..={MAX_CLAIMS_BYTES} bytes"
        )
    return adapter_support.validate_compact_json_object(
        raw, "recomputation registry claims"
    )


def signing_payload(claims_raw: bytes, kind: str, key_id: str) -> bytes:
    """Construct ``domain || {key_id,claims}`` without claims reserialization."""

    claims_raw = validate_claims_bytes(claims_raw)
    domain = SIGNING_DOMAINS.get(kind)
    if domain is None:
        raise SignerError("recomputation registry signing kind is unsupported")
    if not adapter_support.safe_key_id(key_id):
        raise SignerError(
            "key_id must be 1..128 ASCII alphanumeric, '_', '-', or '.' characters"
        )
    return (
        domain
        + b'{"key_id":'
        + _json_string(key_id)
        + b',"claims":'
        + claims_raw
        + b"}"
    )


def signed_envelope(
    claims_raw: bytes,
    kind: str,
    private_key_path: Path,
    key_id: str,
    *,
    private_key_bytes: bytes | None = None,
) -> bytes:
    """Return a compact signed envelope preserving the exact claims bytes."""

    payload = signing_payload(claims_raw, kind, key_id)
    signature = adapter_support.sign_ed25519_payload(
        payload,
        private_key_path,
        private_key_bytes=private_key_bytes,
        private_key_label="recomputation registry signer",
    )
    return (
        b'{"claims":'
        + claims_raw
        + b',"signature":{"key_id":'
        + _json_string(key_id)
        + b',"signature_hex":"'
        + signature.hex().encode("ascii")
        + b'"}}'
    )


def sign_file(
    claims_path: Path,
    kind: str,
    private_key_path: Path,
    key_id: str,
    output_path: Path,
) -> bytes:
    """Read immutable inputs once and atomically write one signed envelope."""

    protected = [claims_path, private_key_path]
    with adapter_support.FrozenAtomicOutput(output_path, protected) as frozen_output:
        claims_raw, claims_identity = crypto_support.read_bounded_with_identity(
            claims_path,
            MAX_CLAIMS_BYTES,
            "recomputation registry claims",
        )
        claims_raw = validate_claims_bytes(claims_raw)
        (
            private_key_bytes,
            private_key_identity,
        ) = crypto_support.read_bounded_private_with_identity(
            private_key_path,
            attestation_support.MAX_KEY_BYTES,
            "Ed25519 private key",
        )
        frozen_output.protect_identities({claims_identity, private_key_identity})
        envelope = signed_envelope(
            claims_raw,
            kind,
            private_key_path,
            key_id,
            private_key_bytes=private_key_bytes,
        )
        frozen_output.write_bytes(envelope)
    return envelope


def main() -> int:
    args = parse_args()
    try:
        output = Path(args.output)
        sign_file(
            Path(args.claims),
            args.kind,
            Path(args.private_key),
            args.key_id,
            output,
        )
        print(f"recomputation-registry signed envelope written to {output}")
        return 0
    except (SignerError, UnicodeDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
