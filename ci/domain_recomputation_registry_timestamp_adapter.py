#!/usr/bin/env python3

"""Issue trusted-time receipts for recomputation-registry checkpoints.

This module is a deliberately closed profile over
``domain_result_timestamp_adapter``.  The hardened RFC 3161, PKIX-path,
historical-CRL, immutable-input, private-key, and atomic-output checks remain
owned by that implementation.  This profile accepts only registry checkpoints
and uses a registry-specific schema and Ed25519 signature domain.
"""

import sys
from pathlib import Path

try:
    from ci import domain_result_timestamp_adapter as adapter_support
except ModuleNotFoundError:  # Direct execution from the ci/ directory.
    import domain_result_timestamp_adapter as adapter_support


TRUSTED_TIMESTAMP_SCHEMA_VERSION = (
    "aura.domain.recomputation_attempt_registry_timestamp_verification.v1"
)
TRUSTED_TIMESTAMP_PROTOCOL = adapter_support.TRUSTED_TIMESTAMP_PROTOCOL
SIGNED_PAYLOAD_DOMAIN = (
    b"aura.domain.recomputation-attempt-registry-trusted-timestamp.v1\x00"
)
SUBJECT_KINDS = ("registry_checkpoint",)

RECOMPUTATION_REGISTRY_TIMESTAMP_PROFILE = adapter_support.TimestampReceiptProfile(
    schema_version=TRUSTED_TIMESTAMP_SCHEMA_VERSION,
    protocol=TRUSTED_TIMESTAMP_PROTOCOL,
    signed_payload_domain=SIGNED_PAYLOAD_DOMAIN,
    subject_kinds=SUBJECT_KINDS,
    cli_label="domain-recomputation-registry",
)

AdapterError = adapter_support.AdapterError
FrozenAtomicOutput = adapter_support.FrozenAtomicOutput
CLAIM_FIELDS = adapter_support.CLAIM_FIELDS


def signing_payload(claims: dict, key_id: str) -> bytes:
    """Return the exact registry-checkpoint timestamp signature payload."""

    return adapter_support.signing_payload(
        claims,
        key_id,
        profile=RECOMPUTATION_REGISTRY_TIMESTAMP_PROFILE,
    )


def sign_claims(
    claims: dict,
    private_key_path: Path,
    key_id: str,
    *,
    private_key_bytes: bytes | None = None,
) -> dict:
    """Sign registry timestamp claims with the configured verifier key."""

    return adapter_support.sign_claims(
        claims,
        private_key_path,
        key_id,
        private_key_bytes=private_key_bytes,
        profile=RECOMPUTATION_REGISTRY_TIMESTAMP_PROFILE,
    )


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
    """Verify original RFC 3161 evidence and issue the registry receipt type."""

    return adapter_support.create_trusted_timestamp_receipt(
        subject_path=subject_path,
        subject_kind=subject_kind,
        request_path=request_path,
        response_path=response_path,
        ca_file_path=ca_file_path,
        untrusted_chain_path=untrusted_chain_path,
        revocation_crl_paths=revocation_crl_paths,
        expected_policy_oid=expected_policy_oid,
        expected_tsa_spki_sha256=expected_tsa_spki_sha256,
        private_key_path=private_key_path,
        key_id=key_id,
        frozen_output=frozen_output,
        profile=RECOMPUTATION_REGISTRY_TIMESTAMP_PROFILE,
    )


def parse_args():
    """Parse the shared request/verify-sign CLI under the closed profile."""

    return adapter_support.parse_args(RECOMPUTATION_REGISTRY_TIMESTAMP_PROFILE)


def main() -> int:
    return adapter_support.main(RECOMPUTATION_REGISTRY_TIMESTAMP_PROFILE)


if __name__ == "__main__":
    sys.exit(main())
