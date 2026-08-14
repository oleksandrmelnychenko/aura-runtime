import base64
import copy
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from ci import pilot_signoff_verification as signoff


RELEASE_REVISION = "475f2c18869617d290ec3152e9ba6b10aa903592"
PRIVATE_KEY_DER_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
FIXED_POLICY_SHA256 = (
    "60765fb0eea3fc68f0f1dcbe1154774dbc193c8e059256ee7e2860f99543551d"
)
FIXED_FIRST_SIGNATURE = (
    "/2J0eiR/rnP21cVkkkoX3iICIAwki335TbCPJ3LmkKWrJCqMwqhXKiP9ojCn4QKQ"
    "D1659BB2xN1+cNAwni+4DA=="
)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class PilotSignoffVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_keys = [
            PRIVATE_KEY_DER_PREFIX + bytes(range(start, start + 32))
            for start in (0, 32, 64, 96)
        ]
        cls.public_key_der = [
            cls._public_key_from_private(private_key)
            for private_key in cls.private_keys
        ]
        roles = [
            {
                "area": area,
                "reviewer": f"reviewer-{index + 1}",
                "key_id": f"pilot-key-{index + 1}",
                "public_key_hex": cls.public_key_der[index][-32:].hex(),
            }
            for index, area in enumerate(signoff.REQUIRED_REVIEW_AREAS)
        ]
        cls.policy = {
            "schema_version": signoff.TRUST_POLICY_SCHEMA_VERSION,
            "policy_id": "pilot-policy-2026q3",
            "policy_epoch": 7,
            "roles": roles,
        }
        cls.policy_digest = signoff.trust_policy_sha256(cls.policy)
        attestations = []
        for index, (role, public_key_der) in enumerate(
            zip(roles, cls.public_key_der, strict=True)
        ):
            claims = {
                "schema_version": signoff.CLAIM_SCHEMA_VERSION,
                "policy_id": cls.policy["policy_id"],
                "policy_epoch": cls.policy["policy_epoch"],
                "trust_policy_sha256": cls.policy_digest,
                "area": role["area"],
                "reviewer": role["reviewer"],
                "status": "approved",
                "reviewed_at_utc": f"2026-08-14T10:0{index}:00Z",
                "notes": None if index % 2 else f"approved fixture {index + 1}",
                "release_revision": RELEASE_REVISION,
            }
            attestation = {
                "schema_version": signoff.ATTESTATION_SCHEMA_VERSION,
                "signature_algorithm": signoff.SIGNATURE_ALGORITHM,
                "key_id": role["key_id"],
                "public_key_spki_sha256": sha256(public_key_der).hexdigest(),
                "claims": claims,
                "signature_base64": "",
            }
            attestation["signature_base64"] = cls._sign(
                cls.private_keys[index],
                signoff.canonical_attestation_claims(attestation),
            )
            attestations.append(attestation)
        cls.bundle = {
            "schema_version": signoff.BUNDLE_SCHEMA_VERSION,
            "release_revision": RELEASE_REVISION,
            "attestations": attestations,
        }

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _public_key_from_private(private_key: bytes) -> bytes:
        with tempfile.NamedTemporaryFile() as key_file:
            key_file.write(private_key)
            key_file.flush()
            return subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-inform",
                    "DER",
                    "-in",
                    key_file.name,
                    "-pubout",
                    "-outform",
                    "DER",
                ],
                check=True,
                capture_output=True,
            ).stdout

    @staticmethod
    def _sign(private_key: bytes, payload: bytes) -> str:
        with (
            tempfile.NamedTemporaryFile() as key_file,
            tempfile.NamedTemporaryFile() as payload_file,
        ):
            key_file.write(private_key)
            key_file.flush()
            payload_file.write(payload)
            payload_file.flush()
            signature = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    key_file.name,
                    "-in",
                    payload_file.name,
                ],
                check=True,
                capture_output=True,
            ).stdout
        if len(signature) != 64:
            raise AssertionError("fixture did not produce an Ed25519 signature")
        return base64.b64encode(signature).decode("ascii")

    @classmethod
    def _resign(cls, bundle: dict, index: int) -> None:
        attestation = bundle["attestations"][index]
        attestation["signature_base64"] = cls._sign(
            cls.private_keys[index],
            signoff.canonical_attestation_claims(attestation),
        )

    @staticmethod
    def _write_json(path: Path, payload: dict) -> None:
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )

    def _verify(self, bundle: dict | None = None, policy: dict | None = None) -> dict:
        return signoff.verify_bundle(
            copy.deepcopy(self.bundle if bundle is None else bundle),
            copy.deepcopy(self.policy if policy is None else policy),
            self.policy_digest,
            RELEASE_REVISION,
        )

    def _cli(
        self,
        bundle_path: Path,
        policy_path: Path,
        output: Path,
        signoffs_output: Path,
        *,
        digest: str | None = None,
        revision: str = RELEASE_REVISION,
        require_pass: bool = True,
        command: str = "verify",
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable,
            Path(signoff.__file__).as_posix(),
            command,
            "--bundle",
            bundle_path.as_posix(),
            "--trust-policy",
            policy_path.as_posix(),
            "--expected-trust-policy-sha256",
            digest or self.policy_digest,
            "--release-revision",
            revision,
            "--output",
            output.as_posix(),
            "--signoffs-output",
            signoffs_output.as_posix(),
        ]
        if require_pass:
            arguments.append("--require-pass")
        return subprocess.run(arguments, text=True, capture_output=True, check=False)

    def test_fixed_vector_pins_policy_and_attestation_domains(self) -> None:
        self.assertEqual(self.policy_digest, FIXED_POLICY_SHA256)
        self.assertEqual(
            self.bundle["attestations"][0]["signature_base64"],
            FIXED_FIRST_SIGNATURE,
        )
        self.assertTrue(
            signoff.canonical_attestation_claims(self.bundle["attestations"][0]).startswith(
                b"aura.pilot-review-signoff-attestation.v1\x00{"
            )
        )
        canonical_policy = json.dumps(
            self.policy,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
        self.assertEqual(
            self.policy_digest,
            sha256(b"aura.pilot-signoff-trust-policy.v1\x00" + canonical_policy).hexdigest(),
        )

    def test_four_role_bundle_verifies_and_projects_exact_v2(self) -> None:
        report = self._verify()
        self.assertEqual(set(report), signoff.REPORT_FIELDS)
        self.assertEqual(report["schema_version"], signoff.VERIFICATION_SCHEMA_VERSION)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["release_revision"], RELEASE_REVISION)
        self.assertEqual(report["trust_policy_sha256"], self.policy_digest)
        self.assertEqual(report["policy_id"], self.policy["policy_id"])
        self.assertEqual(report["policy_epoch"], self.policy["policy_epoch"])
        self.assertEqual(report["signature_algorithm"], "Ed25519")
        self.assertEqual(report["required_review_areas"], list(signoff.REQUIRED_REVIEW_AREAS))
        self.assertEqual(report["verified_signoff_count"], 4)
        self.assertEqual(report["distinct_signer_count"], 4)
        self.assertEqual(len(set(report["signer_spki_sha256"])), 4)
        self.assertEqual(
            report["signer_spki_set_sha256"],
            signoff.signer_spki_set_sha256(report["signer_spki_sha256"]),
        )
        projection = signoff.validate_verification_report(
            report, self.policy, self.policy_digest, RELEASE_REVISION
        )
        self.assertEqual(
            projection,
            {
                "schema_version": signoff.SIGNOFFS_SCHEMA_VERSION,
                "release_revision": RELEASE_REVISION,
                "signoffs": [
                    {
                        field: attestation["claims"][field]
                        for field in (
                            "area",
                            "reviewer",
                            "status",
                            "reviewed_at_utc",
                            "notes",
                            "release_revision",
                        )
                    }
                    for attestation in self.bundle["attestations"]
                ],
            },
        )
        self.assertEqual(report["signoff_set_sha256"], signoff.signoff_set_sha256(projection))

    def test_report_is_self_contained_without_trusted_public_keys(self) -> None:
        report = self._verify()
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("public_key_hex", serialized)
        for role in self.policy["roles"]:
            self.assertNotIn(role["public_key_hex"], serialized)
        self.assertEqual(report["attestations"], self.bundle["attestations"])

    def test_trust_policy_schema_and_scalar_types_are_closed(self) -> None:
        mutations = {
            "not object": lambda _: [],
            "missing field": lambda value: value.pop("policy_id"),
            "extra field": lambda value: value.__setitem__("extra", True),
            "wrong schema": lambda value: value.__setitem__("schema_version", "v0"),
            "unsafe policy ID": lambda value: value.__setitem__("policy_id", "has spaces"),
            "unicode policy ID": lambda value: value.__setitem__("policy_id", "policý"),
            "boolean epoch": lambda value: value.__setitem__("policy_epoch", True),
            "zero epoch": lambda value: value.__setitem__("policy_epoch", 0),
            "negative epoch": lambda value: value.__setitem__("policy_epoch", -1),
            "oversized epoch": lambda value: value.__setitem__(
                "policy_epoch", signoff.MAX_POLICY_EPOCH + 1
            ),
            "roles mapping": lambda value: value.__setitem__("roles", {}),
            "three roles": lambda value: value.__setitem__("roles", value["roles"][:3]),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                policy: object = copy.deepcopy(self.policy)
                replacement = mutation(policy)
                if replacement is not None:
                    policy = replacement
                with self.assertRaises(signoff.PilotSignoffError):
                    signoff.validate_trust_policy(policy)

    def test_trust_policy_requires_exact_order_and_role_separation(self) -> None:
        mutations = {
            "swapped roles": lambda value: value["roles"].__setitem__(
                slice(0, 2), reversed(value["roles"][:2])
            ),
            "role missing field": lambda value: value["roles"][0].pop("key_id"),
            "role extra field": lambda value: value["roles"][0].__setitem__("extra", 1),
            "empty reviewer": lambda value: value["roles"][0].__setitem__("reviewer", ""),
            "NUL reviewer": lambda value: value["roles"][0].__setitem__(
                "reviewer", "reviewer\x00one"
            ),
            "oversized reviewer": lambda value: value["roles"][0].__setitem__(
                "reviewer", "x" * (signoff.MAX_REVIEWER_BYTES + 1)
            ),
            "unsafe key ID": lambda value: value["roles"][0].__setitem__(
                "key_id", "key with spaces"
            ),
            "uppercase public key": lambda value: value["roles"][0].__setitem__(
                "public_key_hex", value["roles"][0]["public_key_hex"].upper()
            ),
            "short public key": lambda value: value["roles"][0].__setitem__(
                "public_key_hex", "00"
            ),
            "zero public key": lambda value: value["roles"][0].__setitem__(
                "public_key_hex", "0" * 64
            ),
            "same reviewer different key": lambda value: value["roles"][1].__setitem__(
                "reviewer", value["roles"][0]["reviewer"]
            ),
            "duplicate key ID": lambda value: value["roles"][1].__setitem__(
                "key_id", value["roles"][0]["key_id"]
            ),
            "duplicate raw key": lambda value: value["roles"][1].__setitem__(
                "public_key_hex", value["roles"][0]["public_key_hex"]
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                policy = copy.deepcopy(self.policy)
                mutation(policy)
                with self.assertRaises(signoff.PilotSignoffError):
                    signoff.validate_trust_policy(policy)

    def test_identity_key_and_universal_forged_signature_are_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        identity_key = bytes([1]) + bytes(31)
        policy["roles"][0]["public_key_hex"] = identity_key.hex()
        with self.assertRaisesRegex(
            signoff.PilotSignoffError, "prime-order point"
        ):
            signoff.validate_trust_policy(policy)

        # OpenSSL 3.6 accepts this signature for arbitrary messages when the
        # policy key is the encoded Ed25519 identity.  Policy validation must
        # reject the key before the backend can turn that into an approval.
        forged = copy.deepcopy(self.bundle)
        forged_attestation = forged["attestations"][0]
        forged_attestation["public_key_spki_sha256"] = sha256(
            signoff.ED25519_SPKI_PREFIX + identity_key
        ).hexdigest()
        forged_attestation["signature_base64"] = base64.b64encode(
            identity_key + bytes(32)
        ).decode("ascii")
        policy_digest = sha256(
            signoff.TRUST_POLICY_DOMAIN + signoff._canonical_json(policy)
        ).hexdigest()
        for attestation in forged["attestations"]:
            attestation["claims"]["trust_policy_sha256"] = policy_digest
        with self.assertRaisesRegex(
            signoff.PilotSignoffError, "prime-order point"
        ):
            signoff.verify_bundle(
                forged,
                policy,
                policy_digest,
                RELEASE_REVISION,
            )

    def test_signature_R_and_scalar_must_be_canonical_prime_order_values(self) -> None:
        for label, signature in (
            ("identity R", bytes([1]) + bytes(31) + bytes(32)),
            (
                "non-canonical scalar",
                base64.b64decode(self.bundle["attestations"][0]["signature_base64"])[
                    :32
                ]
                + signoff.ED25519_SUBGROUP_ORDER.to_bytes(32, "little"),
            ),
        ):
            with self.subTest(label=label):
                bundle = copy.deepcopy(self.bundle)
                bundle["attestations"][0]["signature_base64"] = base64.b64encode(
                    signature
                ).decode("ascii")
                with self.assertRaises(signoff.PilotSignoffError):
                    self._verify(bundle=bundle)

    def test_bundle_envelope_and_caller_pins_fail_closed(self) -> None:
        mutations = {
            "missing field": lambda value: value.pop("attestations"),
            "extra field": lambda value: value.__setitem__("extra", True),
            "wrong schema": lambda value: value.__setitem__("schema_version", "v0"),
            "wrong release": lambda value: value.__setitem__("release_revision", "a" * 40),
            "three attestations": lambda value: value.__setitem__(
                "attestations", value["attestations"][:3]
            ),
            "mapping attestations": lambda value: value.__setitem__("attestations", {}),
            "swapped attestations": lambda value: value["attestations"].__setitem__(
                slice(0, 2), reversed(value["attestations"][:2])
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                bundle = copy.deepcopy(self.bundle)
                mutation(bundle)
                with self.assertRaises(signoff.PilotSignoffError):
                    self._verify(bundle=bundle)
        for digest in ("0" * 64, self.policy_digest.upper(), "not-a-digest"):
            with self.subTest(digest=digest):
                with self.assertRaises(signoff.PilotSignoffError):
                    signoff.verify_bundle(
                        self.bundle, self.policy, digest, RELEASE_REVISION
                    )
        for revision in ("a" * 40, RELEASE_REVISION.upper(), "short"):
            with self.subTest(revision=revision):
                with self.assertRaises(signoff.PilotSignoffError):
                    signoff.verify_bundle(
                        self.bundle, self.policy, self.policy_digest, revision
                    )

    def test_attestation_wrapper_is_closed_and_signature_is_strict(self) -> None:
        mutations = {
            "missing wrapper field": lambda attestation: attestation.pop("key_id"),
            "extra wrapper field": lambda attestation: attestation.__setitem__("extra", 1),
            "wrong schema": lambda attestation: attestation.__setitem__(
                "schema_version", "v0"
            ),
            "wrong algorithm": lambda attestation: attestation.__setitem__(
                "signature_algorithm", "Ed448"
            ),
            "wrong key ID": lambda attestation: attestation.__setitem__(
                "key_id", "pilot-key-2"
            ),
            "wrong SPKI": lambda attestation: attestation.__setitem__(
                "public_key_spki_sha256", "0" * 64
            ),
            "signature not text": lambda attestation: attestation.__setitem__(
                "signature_base64", []
            ),
            "bad base64": lambda attestation: attestation.__setitem__(
                "signature_base64", "***"
            ),
            "short signature": lambda attestation: attestation.__setitem__(
                "signature_base64", base64.b64encode(b"x" * 63).decode("ascii")
            ),
            "tampered signature": lambda attestation: attestation.__setitem__(
                "signature_base64",
                base64.b64encode(
                    bytes([base64.b64decode(attestation["signature_base64"])[0] ^ 1])
                    + base64.b64decode(attestation["signature_base64"])[1:]
                ).decode("ascii"),
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                bundle = copy.deepcopy(self.bundle)
                mutation(bundle["attestations"][0])
                with self.assertRaises(signoff.PilotSignoffError):
                    self._verify(bundle=bundle)

    def test_claim_schema_types_role_mapping_and_approval_are_strict(self) -> None:
        mutations = {
            "missing claim": lambda claims: claims.pop("notes"),
            "extra claim": lambda claims: claims.__setitem__("extra", True),
            "wrong schema": lambda claims: claims.__setitem__("schema_version", "v0"),
            "wrong policy ID": lambda claims: claims.__setitem__("policy_id", "other"),
            "boolean epoch": lambda claims: claims.__setitem__("policy_epoch", True),
            "wrong epoch": lambda claims: claims.__setitem__("policy_epoch", 8),
            "wrong policy digest": lambda claims: claims.__setitem__(
                "trust_policy_sha256", "0" * 64
            ),
            "wrong area": lambda claims: claims.__setitem__(
                "area", signoff.REQUIRED_REVIEW_AREAS[1]
            ),
            "wrong reviewer": lambda claims: claims.__setitem__("reviewer", "reviewer-2"),
            "unknown status": lambda claims: claims.__setitem__("status", "yes"),
            "timezone offset": lambda claims: claims.__setitem__(
                "reviewed_at_utc", "2026-08-14T12:00:00+02:00"
            ),
            "fractional timestamp": lambda claims: claims.__setitem__(
                "reviewed_at_utc", "2026-08-14T10:00:00.000Z"
            ),
            "invalid calendar date": lambda claims: claims.__setitem__(
                "reviewed_at_utc", "2026-02-30T10:00:00Z"
            ),
            "notes mapping": lambda claims: claims.__setitem__("notes", {}),
            "notes NUL": lambda claims: claims.__setitem__("notes", "bad\x00notes"),
            "notes oversized": lambda claims: claims.__setitem__(
                "notes", "x" * (signoff.MAX_NOTES_BYTES + 1)
            ),
            "wrong release": lambda claims: claims.__setitem__(
                "release_revision", "a" * 40
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                bundle = copy.deepcopy(self.bundle)
                mutation(bundle["attestations"][0]["claims"])
                self._resign(bundle, 0)
                with self.assertRaises(signoff.PilotSignoffError):
                    self._verify(bundle=bundle)

    def test_valid_signed_claim_tampering_is_detected(self) -> None:
        for field, value in (
            ("notes", "changed after signing"),
            ("reviewed_at_utc", "2026-08-14T11:00:00Z"),
        ):
            with self.subTest(field=field):
                bundle = copy.deepcopy(self.bundle)
                bundle["attestations"][0]["claims"][field] = value
                with self.assertRaisesRegex(signoff.PilotSignoffError, "signature"):
                    self._verify(bundle=bundle)

    def test_only_four_approved_claims_yield_pass(self) -> None:
        expected_status = {
            "pending": "blocked",
            "needs_changes": "fail",
        }
        for claim_status, report_status in expected_status.items():
            with self.subTest(claim_status=claim_status):
                bundle = copy.deepcopy(self.bundle)
                bundle["attestations"][0]["claims"]["status"] = claim_status
                self._resign(bundle, 0)
                report = self._verify(bundle=bundle)
                self.assertEqual(report["status"], report_status)
                projection = signoff.validate_verification_report(
                    report, self.policy, self.policy_digest, RELEASE_REVISION
                )
                self.assertEqual(projection["signoffs"][0]["status"], claim_status)

    def test_policy_rotation_and_release_replay_are_rejected(self) -> None:
        rotated = copy.deepcopy(self.policy)
        rotated["policy_epoch"] += 1
        rotated_digest = signoff.trust_policy_sha256(rotated)
        with self.assertRaises(signoff.PilotSignoffError):
            signoff.verify_bundle(
                self.bundle, rotated, rotated_digest, RELEASE_REVISION
            )

        reviewer_rotated = copy.deepcopy(self.policy)
        reviewer_rotated["roles"][0]["reviewer"] = "replacement-reviewer"
        reviewer_digest = signoff.trust_policy_sha256(reviewer_rotated)
        with self.assertRaises(signoff.PilotSignoffError):
            signoff.verify_bundle(
                self.bundle, reviewer_rotated, reviewer_digest, RELEASE_REVISION
            )

        replay = copy.deepcopy(self.bundle)
        replay["release_revision"] = "a" * 40
        replay["attestations"][0]["claims"]["release_revision"] = "a" * 40
        self._resign(replay, 0)
        with self.assertRaises(signoff.PilotSignoffError):
            signoff.verify_bundle(replay, self.policy, self.policy_digest, "a" * 40)

    def test_verification_report_is_closed_and_fully_recomputed(self) -> None:
        report = self._verify()
        mutations = {
            "missing field": lambda value: value.pop("policy_id"),
            "extra field": lambda value: value.__setitem__("public_keys", []),
            "schema": lambda value: value.__setitem__("schema_version", "v0"),
            "status": lambda value: value.__setitem__("status", "fail"),
            "release": lambda value: value.__setitem__("release_revision", "a" * 40),
            "policy digest": lambda value: value.__setitem__("trust_policy_sha256", "0" * 64),
            "policy ID": lambda value: value.__setitem__("policy_id", "other"),
            "policy epoch": lambda value: value.__setitem__("policy_epoch", 8),
            "algorithm": lambda value: value.__setitem__("signature_algorithm", "Ed448"),
            "areas": lambda value: value["required_review_areas"].reverse(),
            "verified count": lambda value: value.__setitem__("verified_signoff_count", 3),
            "distinct count": lambda value: value.__setitem__("distinct_signer_count", 3),
            "signoff digest": lambda value: value.__setitem__("signoff_set_sha256", "0" * 64),
            "signer list": lambda value: value["signer_spki_sha256"].reverse(),
            "signer set digest": lambda value: value.__setitem__(
                "signer_spki_set_sha256", "0" * 64
            ),
            "attestation order": lambda value: value["attestations"].reverse(),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                tampered = copy.deepcopy(report)
                mutation(tampered)
                with self.assertRaises(signoff.PilotSignoffError):
                    signoff.validate_verification_report(
                        tampered, self.policy, self.policy_digest, RELEASE_REVISION
                    )

    def test_report_reverification_detects_embedded_attestation_tampering(self) -> None:
        report = self._verify()
        report["attestations"][0]["claims"]["notes"] = "tampered report"
        with self.assertRaisesRegex(signoff.PilotSignoffError, "signature"):
            signoff.validate_verification_report(
                report, self.policy, self.policy_digest, RELEASE_REVISION
            )

    def test_strict_loaders_reject_duplicate_nonfinite_and_nonobject_json(self) -> None:
        invalid = {
            "duplicate": b'{"schema_version":"x","schema_version":"y"}',
            "NaN": b'{"value":NaN}',
            "infinity": b'{"value":1e999}',
            "invalid UTF-8": b'{"value":"\xff"}',
            "nonobject": b"[]",
        }
        for label, raw in invalid.items():
            with self.subTest(label=label):
                path = self.root / f"{label}.json"
                path.write_bytes(raw)
                with self.assertRaises(signoff.PilotSignoffError):
                    signoff.load_bundle(path)

    def test_loaders_are_bounded_and_reject_symlink_and_fifo(self) -> None:
        policy_path = self.root / "policy.json"
        self._write_json(policy_path, self.policy)
        self.assertEqual(signoff.load_trust_policy(policy_path), self.policy)
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"{" + b" " * signoff.MAX_BUNDLE_BYTES + b"}")
        with self.assertRaises(signoff.crypto_support.AttestationError):
            signoff.load_bundle(oversized)
        if os.name != "nt":
            symbolic = self.root / "policy-link.json"
            symbolic.symlink_to(policy_path)
            with self.assertRaises(signoff.crypto_support.AttestationError):
                signoff.load_trust_policy(symbolic)
            fifo = self.root / "bundle.fifo"
            os.mkfifo(fifo)
            with self.assertRaises(signoff.crypto_support.AttestationError):
                signoff.load_bundle(fifo)

    def test_cli_writes_exact_atomic_report_and_projection(self) -> None:
        bundle_path = self.root / "bundle.json"
        policy_path = self.root / "policy.json"
        output = self.root / "verification.json"
        signoffs_output = self.root / "signoffs.json"
        self._write_json(bundle_path, self.bundle)
        self._write_json(policy_path, self.policy)
        completed = self._cli(bundle_path, policy_path, output, signoffs_output)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = signoff.load_verification_report(output)
        projection = signoff.validate_verification_report(
            report, self.policy, self.policy_digest, RELEASE_REVISION
        )
        self.assertEqual(json.loads(signoffs_output.read_text(encoding="utf-8")), projection)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(signoffs_output.stat().st_mode), 0o600)

    def test_cli_rejects_invalid_evidence_without_outputs(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["attestations"][0]["claims"]["status"] = "not-a-status"
        self._resign(bundle, 0)
        bundle_path = self.root / "bundle.json"
        policy_path = self.root / "policy.json"
        output = self.root / "verification.json"
        signoffs_output = self.root / "signoffs.json"
        self._write_json(bundle_path, bundle)
        self._write_json(policy_path, self.policy)
        completed = self._cli(bundle_path, policy_path, output, signoffs_output)
        self.assertEqual(completed.returncode, 2)
        self.assertFalse(output.exists())
        self.assertFalse(signoffs_output.exists())

    def test_cli_require_pass_distinguishes_verified_nonapproval(self) -> None:
        policy_path = self.root / "policy.json"
        self._write_json(policy_path, self.policy)
        for claim_status, expected_report_status in (
            ("pending", "blocked"),
            ("needs_changes", "fail"),
        ):
            with self.subTest(claim_status=claim_status):
                bundle = copy.deepcopy(self.bundle)
                bundle["attestations"][0]["claims"]["status"] = claim_status
                self._resign(bundle, 0)
                bundle_path = self.root / f"bundle-{claim_status}.json"
                output = self.root / f"verification-{claim_status}.json"
                projection = self.root / f"signoffs-{claim_status}.json"
                self._write_json(bundle_path, bundle)
                completed = self._cli(
                    bundle_path, policy_path, output, projection, require_pass=True
                )
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertEqual(
                    json.loads(output.read_text(encoding="utf-8"))["status"],
                    expected_report_status,
                )
                output.unlink()
                projection.unlink()
                completed = self._cli(
                    bundle_path, policy_path, output, projection, require_pass=False
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_cli_has_no_private_key_or_sign_command(self) -> None:
        completed = subprocess.run(
            [sys.executable, Path(signoff.__file__).as_posix(), "sign", "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("invalid choice", completed.stderr)

    def test_cli_rejects_same_or_symbolic_output_aliases(self) -> None:
        bundle_path = self.root / "bundle.json"
        policy_path = self.root / "policy.json"
        self._write_json(bundle_path, self.bundle)
        self._write_json(policy_path, self.policy)
        same = self.root / "same.json"
        completed = self._cli(bundle_path, policy_path, same, same)
        self.assertEqual(completed.returncode, 2)
        completed = self._cli(
            bundle_path, policy_path, bundle_path, self.root / "signoffs.json"
        )
        self.assertEqual(completed.returncode, 2)
        if os.name != "nt":
            symbolic = self.root / "symbolic-output.json"
            symbolic.symlink_to(bundle_path)
            completed = self._cli(
                bundle_path, policy_path, symbolic, self.root / "projection.json"
            )
            self.assertEqual(completed.returncode, 2)

    @unittest.skipIf(os.name == "nt", "POSIX hard-link semantics")
    def test_cli_rejects_hard_link_output_aliases(self) -> None:
        bundle_path = self.root / "bundle.json"
        policy_path = self.root / "policy.json"
        self._write_json(bundle_path, self.bundle)
        self._write_json(policy_path, self.policy)
        output = self.root / "bundle-hardlink.json"
        os.link(bundle_path, output)
        completed = self._cli(
            bundle_path, policy_path, output, self.root / "projection.json"
        )
        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)

        output.unlink(missing_ok=True)
        projection = self.root / "projection-hardlink.json"
        output.write_text("placeholder\n", encoding="utf-8")
        os.link(output, projection)
        completed = self._cli(bundle_path, policy_path, output, projection)
        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
