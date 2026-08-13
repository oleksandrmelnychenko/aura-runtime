import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ci import domain_recomputation_registry_signer as signer
from ci import temporal_study_timestamp
from ci.test_domain_result_timestamp_adapter import FIXED_ED25519_PRIVATE_KEY


FIXED_REGISTRY_ENTRY_SIGNATURE_HEX = (
    "f13e037d1d8a8ded7f0a807745846990ee78d19dd2772e75987ca61e0581089dd"
    "87908b38fa1746a996b109effec1921b8ba42c075fba2c697e0408eeab95404"
)
FIXED_REGISTRY_CHECKPOINT_OPERATOR_SIGNATURE_HEX = (
    "9a70be41bcef1035f9839886a32d165dfe44e88964270db2a5c3db2591d8db07"
    "c757e2e94c44c7e270a9943ddd641ec11be39310678b41c65fef461b8f2d5c02"
)
FIXED_REGISTRY_CHECKPOINT_WITNESS_SIGNATURE_HEX = (
    "1b352780c9443dfff9b6c16c822b77a2e47eb19e31a41f8714cf465af7636e26"
    "a7ae987720330d2438693888d91a726ef406dd46d2a7aa5a456ba6ddce67ae05"
)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class DomainRecomputationRegistrySignerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.claims = self.root / "registry-entry-claims.json"
        self.claims_raw = (
            b'{"schema_version":'
            b'"aura.domain.recomputation_attempt_registry_entry.v1",'
            b'"registry_id":"registry_2026_01",'
            b'"registry_trust_policy_canonical_sha256":"'
            + b"d" * 64
            + b'","sequence":0,"previous_entry_sha256":null,'
            b'"event":{"event_kind":"attempt_registered","event":{'
            b'"domain_id":"kids","study_id":"study_2026_01",'
            b'"result_id":"result_2026_01",'
            b'"recomputation_id":"recomputation_2026_01",'
            b'"plan_canonical_sha256":"'
            + b"a" * 64
            + b'","plan_timestamp_sha256":"'
            + b"b" * 64
            + b'","custodian_authorization_sha256":"'
            + b"c" * 64
            + b'","custodian_authorization_timestamp_sha256":"'
            + b"d" * 64
            + b'","reproducer_authorization_sha256":"'
            + b"a" * 64
            + b'","reproducer_authorization_timestamp_sha256":"'
            + b"b" * 64
            + b'","run_id":"'
            + b"c" * 64
            + b'","terminal_due_at_ms":1780003600000}},'
            b'"recorded_at_ms":1780000000000,"raw_content_exported":false,'
            b'"public_distribution_permitted":false}'
        )
        self.checkpoint_claims_raw = (
            b'{"schema_version":'
            b'"aura.domain.recomputation_attempt_registry_checkpoint.v1",'
            b'"registry_id":"registry_2026_01",'
            b'"registry_trust_policy_canonical_sha256":"'
            + b"d" * 64
            + b'","entry_count":2,"head_entry_sha256":"'
            + b"a" * 64
            + b'","entries_aggregate_sha256":"'
            + b"b" * 64
            + b'","previous_accepted_anchor_sha256":"'
            + b"c" * 64
            + b'","previous_entry_count":0,"previous_head_entry_sha256":null,'
            b'"previous_entries_aggregate_sha256":"'
            + b"d" * 64
            + b'","pending_attempt_count":0,"completed_at_ms":1780000001000,'
            b'"raw_content_exported":false,"public_distribution_permitted":false}'
        )
        temporal_study_timestamp.write_bytes_atomic(self.claims, self.claims_raw)
        self.private_key = self.root / "registry-operator-private.pem"
        self.public_key = self.root / "registry-operator-public.pem"
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
            "registry_entry": b"aura.domain.recomputation-attempt-registry-entry.v1\x00",
            "registry_checkpoint_operator": b"aura.domain.recomputation-attempt-registry-checkpoint-operator.v1\x00",
            "registry_checkpoint_witness": b"aura.domain.recomputation-attempt-registry-checkpoint-witness.v1\x00",
        }
        self.assertEqual(signer.SIGNING_DOMAINS, expected_domains)
        signed_json = (
            b'{"key_id":"registry_operator","claims":' + self.claims_raw + b"}"
        )
        for kind, domain in expected_domains.items():
            with self.subTest(kind=kind):
                self.assertEqual(
                    signer.signing_payload(self.claims_raw, kind, "registry_operator"),
                    domain + signed_json,
                )

    def test_signed_envelope_preserves_claims_and_has_fixed_signature_vector(self):
        envelope = signer.signed_envelope(
            self.claims_raw,
            "registry_entry",
            self.private_key,
            "registry_operator",
        )

        parsed = json.loads(envelope)
        self.assertTrue(envelope.startswith(b'{"claims":' + self.claims_raw))
        self.assertNotIn(b"\n", envelope)
        self.assertEqual(
            parsed["claims"]["event"]["event_kind"], "attempt_registered"
        )
        self.assertEqual(
            parsed["signature"]["signature_hex"],
            FIXED_REGISTRY_ENTRY_SIGNATURE_HEX,
        )
        self.verify_signature(envelope, "registry_entry")

    def test_domains_produce_distinct_deterministic_signatures(self):
        signatures = {}
        for kind in signer.SIGNING_DOMAINS:
            envelope = signer.signed_envelope(
                self.claims_raw,
                kind,
                self.private_key,
                "registry_operator",
            )
            signatures[kind] = json.loads(envelope)["signature"]["signature_hex"]

        self.assertEqual(len(set(signatures.values())), len(signer.SIGNING_DOMAINS))
        repeated = signer.signed_envelope(
            self.claims_raw,
            "registry_entry",
            self.private_key,
            "registry_operator",
        )
        self.assertEqual(
            json.loads(repeated)["signature"]["signature_hex"],
            signatures["registry_entry"],
        )

    def test_checkpoint_role_signatures_have_fixed_cross_language_vectors(self):
        operator = signer.signed_envelope(
            self.checkpoint_claims_raw,
            "registry_checkpoint_operator",
            self.private_key,
            "registry_operator",
        )
        witness = signer.signed_envelope(
            self.checkpoint_claims_raw,
            "registry_checkpoint_witness",
            self.private_key,
            "registry_witness",
        )

        self.assertEqual(
            json.loads(operator)["signature"]["signature_hex"],
            FIXED_REGISTRY_CHECKPOINT_OPERATOR_SIGNATURE_HEX,
        )
        self.assertEqual(
            json.loads(witness)["signature"]["signature_hex"],
            FIXED_REGISTRY_CHECKPOINT_WITNESS_SIGNATURE_HEX,
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
                    signer.signing_payload(raw, "registry_entry", "registry_operator")

    def test_unknown_kind_and_unsafe_key_id_are_rejected(self):
        for unsupported_kind in (
            "execution_attestation",
            "registry_checkpoint",
            "checkpoint",
            "unknown",
        ):
            with self.subTest(unsupported_kind=unsupported_kind):
                with self.assertRaisesRegex(signer.SignerError, "unsupported"):
                    signer.signing_payload(
                        self.claims_raw, unsupported_kind, "registry_operator"
                    )
        with self.assertRaisesRegex(signer.SignerError, "key_id"):
            signer.signing_payload(self.claims_raw, "registry_entry", "bad key")

    def test_sign_file_is_atomic_and_cannot_alias_an_input(self):
        output = self.root / "signed-registry-entry.json"
        envelope = signer.sign_file(
            self.claims,
            "registry_entry",
            self.private_key,
            "registry_operator",
            output,
        )

        self.assertEqual(output.read_bytes(), envelope)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.verify_signature(envelope, "registry_entry")

        with self.assertRaisesRegex(signer.SignerError, "must not overwrite"):
            signer.sign_file(
                self.claims,
                "registry_entry",
                self.private_key,
                "registry_operator",
                self.claims,
            )
        hardlink = self.root / "claims-hardlink.json"
        os.link(self.claims, hardlink)
        with self.assertRaisesRegex(signer.SignerError, "must not overwrite"):
            signer.sign_file(
                self.claims,
                "registry_entry",
                self.private_key,
                "registry_operator",
                hardlink,
            )

    def test_symbolic_input_and_group_readable_private_key_are_rejected(self):
        symbolic_claims = self.root / "symbolic-claims.json"
        symbolic_claims.symlink_to(self.claims)
        with self.assertRaisesRegex(signer.SignerError, "symbolic"):
            signer.sign_file(
                symbolic_claims,
                "registry_entry",
                self.private_key,
                "registry_operator",
                self.root / "symbolic-claims-output.json",
            )

        os.chmod(self.private_key, 0o640)
        with self.assertRaisesRegex(signer.SignerError, "permissions"):
            signer.sign_file(
                self.claims,
                "registry_entry",
                self.private_key,
                "registry_operator",
                self.root / "permissions-output.json",
            )

    def test_cli_writes_the_exact_witness_envelope_shape(self):
        output = self.root / "cli-signed-registry-checkpoint.json"
        script = Path(__file__).with_name("domain_recomputation_registry_signer.py")

        subprocess.run(
            [
                sys.executable,
                script.as_posix(),
                "--claims",
                self.claims.as_posix(),
                "--kind",
                "registry_checkpoint_witness",
                "--private-key",
                self.private_key.as_posix(),
                "--key-id",
                "registry_witness",
                "--output",
                output.as_posix(),
            ],
            check=True,
            capture_output=True,
        )

        envelope = output.read_bytes()
        self.assertTrue(envelope.startswith(b'{"claims":' + self.claims_raw))
        self.assertFalse(envelope.endswith(b"\n"))
        self.verify_signature(envelope, "registry_checkpoint_witness")


if __name__ == "__main__":
    unittest.main()
