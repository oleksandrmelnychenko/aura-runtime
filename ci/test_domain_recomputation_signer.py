import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ci import domain_recomputation_signer as signer
from ci import temporal_study_timestamp
from ci.test_domain_result_timestamp_adapter import FIXED_ED25519_PRIVATE_KEY


FIXED_EXECUTION_ATTESTATION_SIGNATURE_HEX = (
    "27d60b63b4e2f70e5ffa69562366e089bf64c1d8caab6c3d285e440a77dda6d870"
    "8ac6f027ab9dca9efed38c47e7dc52b239a40124839c8e8c6a5f4ae4dc6008"
)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class DomainRecomputationSignerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.claims = self.root / "execution-claims.json"
        self.claims_raw = (
            b'{"schema_version":"aura.domain.recomputation_execution_attestation.v1",'
            b'"recomputation_id":"recomputation_2026_01",'
            b'"run_id":"' + b"a" * 64 + b'","attempt_ordinal":0,'
            b'"plan_canonical_sha256":"' + b"b" * 64 + b'",'
            b'"signed_start_commitment_sha256":"' + b"c" * 64 + b'",'
            b'"start_timestamp_sha256":"' + b"d" * 64 + b'",'
            b'"observed_reproduction_manifest_canonical_sha256":"'
            + b"a" * 64
            + b'","observed_execution_specification_canonical_sha256":"'
            + b"b" * 64
            + b'","disposition":"succeeded","process_exit_code":0,'
            b'"failure_kind":null,"output_artifact_manifest_sha256":"'
            + b"c" * 64
            + b'","execution_transcript_sha256":"'
            + b"d" * 64
            + b'","no_deviation_manifest_canonical_sha256":"'
            + b"a" * 64
            + b'","normalized_result_canonical_sha256":"'
            + b"b" * 64
            + b'","observed_wall_clock_ms":1000,"observed_cpu_time_ms":750,'
            b'"observed_peak_rss_bytes":268435456,"observed_output_bytes":1048576,'
            b'"declared_started_at_ms":1780000000000,'
            b'"declared_completed_at_ms":1780000001000,"raw_content_exported":false}'
        )
        temporal_study_timestamp.write_bytes_atomic(self.claims, self.claims_raw)
        self.private_key = self.root / "recomputation-executor-private.pem"
        self.public_key = self.root / "recomputation-executor-public.pem"
        temporal_study_timestamp.write_bytes_atomic(
            self.private_key, FIXED_ED25519_PRIVATE_KEY
        )
        os.chmod(self.private_key, 0o600)
        public_key = temporal_study_timestamp.run_openssl(
            ["pkey", "-in", self.private_key.as_posix(), "-pubout"]
        )
        temporal_study_timestamp.write_bytes_atomic(self.public_key, public_key)

    def tearDown(self):
        self.temporary.cleanup()

    def verify_signature(self, envelope: bytes, kind: str):
        parsed = json.loads(envelope.decode("utf-8"))
        payload = signer.signing_payload(
            self.claims_raw,
            kind,
            parsed["signature"]["key_id"],
        )
        with (
            tempfile.NamedTemporaryFile() as payload_file,
            tempfile.NamedTemporaryFile() as signature_file,
        ):
            payload_file.write(payload)
            payload_file.flush()
            signature_file.write(bytes.fromhex(parsed["signature"]["signature_hex"]))
            signature_file.flush()
            temporal_study_timestamp.run_openssl(
                [
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    self.public_key.as_posix(),
                    "-sigfile",
                    signature_file.name,
                    "-in",
                    payload_file.name,
                ]
            )

    def test_every_kind_has_the_exact_required_domain_and_payload_order(self):
        expected_domains = {
            "custodian_authorization": b"aura.domain.recomputation-custodian-authorization.v1\x00",
            "independent_reproducer_authorization": b"aura.domain.recomputation-reproducer-authorization.v1\x00",
            "execution_start_commitment": b"aura.domain.recomputation-execution-start.v1\x00",
            "execution_attestation": b"aura.domain.recomputation-execution-attestation.v1\x00",
            "recomputation_final_manifest": b"aura.domain.recomputation-final-manifest.v1\x00",
        }
        self.assertEqual(signer.SIGNING_DOMAINS, expected_domains)
        signed_json = (
            b'{"key_id":"recomputation_executor","claims":'
            + self.claims_raw
            + b"}"
        )
        for kind, domain in expected_domains.items():
            with self.subTest(kind=kind):
                self.assertEqual(
                    signer.signing_payload(
                        self.claims_raw, kind, "recomputation_executor"
                    ),
                    domain + signed_json,
                )

    def test_signed_envelope_preserves_claims_bytes_and_signature_verifies(self):
        envelope = signer.signed_envelope(
            self.claims_raw,
            "execution_attestation",
            self.private_key,
            "recomputation_executor",
        )

        self.assertTrue(envelope.startswith(b'{"claims":' + self.claims_raw))
        self.assertNotIn(b"\n", envelope)
        self.assertEqual(json.loads(envelope)["claims"]["disposition"], "succeeded")
        self.assertEqual(len(json.loads(envelope)["signature"]["signature_hex"]), 128)
        self.assertEqual(
            json.loads(envelope)["signature"]["signature_hex"],
            FIXED_EXECUTION_ATTESTATION_SIGNATURE_HEX,
        )
        self.verify_signature(envelope, "execution_attestation")

    def test_domains_produce_distinct_deterministic_signatures(self):
        signatures = {}
        for kind in signer.SIGNING_DOMAINS:
            envelope = signer.signed_envelope(
                self.claims_raw,
                kind,
                self.private_key,
                "recomputation_executor",
            )
            signatures[kind] = json.loads(envelope)["signature"]["signature_hex"]

        self.assertEqual(len(set(signatures.values())), len(signer.SIGNING_DOMAINS))
        repeated = signer.signed_envelope(
            self.claims_raw,
            "execution_attestation",
            self.private_key,
            "recomputation_executor",
        )
        self.assertEqual(
            json.loads(repeated)["signature"]["signature_hex"],
            signatures["execution_attestation"],
        )

    def test_strict_compact_claims_reject_ambiguous_json(self):
        invalid = (
            (b'{"a":1,"a":2}', "duplicate JSON field"),
            (b'{"a":NaN}', "non-finite"),
            (b"[]", "JSON object"),
            (b'{"a": 1}', "compact Rust serde JSON"),
            (b"", "size must be"),
        )
        for raw, message in invalid:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(signer.SignerError, message):
                    signer.signing_payload(raw, "execution_attestation", "executor_2026")

    def test_unknown_kind_and_unsafe_key_id_are_rejected(self):
        for unsigned_kind in (
            "recomputation_plan",
            "comparison_receipt",
            "evidence_custodian_authorization",
            "unknown",
        ):
            with self.subTest(unsigned_kind=unsigned_kind):
                with self.assertRaisesRegex(signer.SignerError, "unsupported"):
                    signer.signing_payload(
                        self.claims_raw, unsigned_kind, "executor_2026"
                    )
        with self.assertRaisesRegex(signer.SignerError, "key_id"):
            signer.signing_payload(self.claims_raw, "execution_attestation", "bad key")

    def test_sign_file_writes_compact_distinct_atomic_output(self):
        output = self.root / "signed-execution-attestation.json"

        envelope = signer.sign_file(
            self.claims,
            "execution_attestation",
            self.private_key,
            "recomputation_executor",
            output,
        )

        self.assertEqual(output.read_bytes(), envelope)
        self.assertEqual(json.loads(envelope)["claims"]["recomputation_id"], "recomputation_2026_01")
        self.verify_signature(envelope, "execution_attestation")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_output_cannot_overwrite_or_hardlink_an_input(self):
        with self.assertRaisesRegex(signer.SignerError, "must not overwrite"):
            signer.sign_file(
                self.claims,
                "execution_attestation",
                self.private_key,
                "recomputation_executor",
                self.claims,
            )
        hardlink = self.root / "claims-hardlink.json"
        os.link(self.claims, hardlink)
        with self.assertRaisesRegex(signer.SignerError, "must not overwrite"):
            signer.sign_file(
                self.claims,
                "execution_attestation",
                self.private_key,
                "recomputation_executor",
                hardlink,
            )

    def test_symbolic_or_group_readable_private_key_is_rejected(self):
        symbolic_claims = self.root / "symbolic-claims.json"
        symbolic_claims.symlink_to(self.claims)
        with self.assertRaisesRegex(signer.SignerError, "symbolic"):
            signer.sign_file(
                symbolic_claims,
                "execution_attestation",
                self.private_key,
                "recomputation_executor",
                self.root / "symbolic-claims-output.json",
            )

        symbolic = self.root / "symbolic-private-key.pem"
        symbolic.symlink_to(self.private_key)
        with self.assertRaisesRegex(signer.SignerError, "symbolic"):
            signer.sign_file(
                self.claims,
                "execution_attestation",
                symbolic,
                "recomputation_executor",
                self.root / "symbolic-output.json",
            )

        os.chmod(self.private_key, 0o640)
        with self.assertRaisesRegex(signer.SignerError, "permissions"):
            signer.sign_file(
                self.claims,
                "execution_attestation",
                self.private_key,
            "recomputation_executor",
                self.root / "permissions-output.json",
            )

    def test_cli_writes_the_same_exact_envelope_shape(self):
        output = self.root / "cli-signed-final-manifest.json"
        script = Path(__file__).with_name("domain_recomputation_signer.py")

        subprocess.run(
            [
                sys.executable,
                script.as_posix(),
                "--claims",
                self.claims.as_posix(),
                "--kind",
                "recomputation_final_manifest",
                "--private-key",
                self.private_key.as_posix(),
                "--key-id",
                "recomputation_executor",
                "--output",
                output.as_posix(),
            ],
            check=True,
            capture_output=True,
        )

        envelope = output.read_bytes()
        self.assertTrue(envelope.startswith(b'{"claims":' + self.claims_raw))
        self.assertFalse(envelope.endswith(b"\n"))
        self.verify_signature(envelope, "recomputation_final_manifest")


if __name__ == "__main__":
    unittest.main()
