# Independent aggregate-recomputation evidence

`aura.domain.independent_recomputation_evidence.v1` records one submitted,
terminal recomputation attempt over the frozen content-free aggregate result from a
validated private reproduction package. The shared validator first reruns the
complete original result-evidence and reproduction-package validators. It then
checks a separate trust policy with five distinct Ed25519 key roles, five
non-timestamp signed envelopes, seven signed RFC 3161 verification receipts,
the retained timestamp material, and a deterministic typed comparison.

This is deliberately narrower than scientific replication. An
`aggregate_exact_match` means that one submitted same-data computation exactly
matched the original aggregate metrics, IEEE-754 agreement bits, conservative
agreement bound, and frozen outcome. It does not test a new sample, population,
labeling process, intervention, or implementation. It also does not prove that
the declared executor was organizationally independent or that the declared
process actually ran outside the key holder's environment. Those remain
governance and execution-assurance assumptions unless a separately approved
trusted-execution mechanism is introduced.

## Closed v1 chain

The validator accepts exactly this order:

1. A canonical plan binds the validated original preregistration, result,
   final manifest, complete evidence bundle, private reproduction package,
   original trust policy, recomputation trust policy, execution specification,
   fixed seeds, environment, binary, source tree, resource ceilings, and
   `deny_all` network policy. The submitted v1 bundle represents one terminal
   attempt and permits no deviations.
2. RFC 3161 trusted time covers the complete plan after the original final
   evidence manifest.
3. The evidence custodian signs the plan, its timestamp, the one authorized
   executor, access/governance scope, expiry, and a fresh 256-bit nonce. A
   second trusted timestamp covers the signed authorization.
4. The independent reproducer signs acceptance of the plan and prior custodian
   chain, the same executor, an independence-record digest, expiry, and an
   independent 256-bit nonce. A third timestamp covers that acceptance.
5. The executor signs a start commitment over the plan, both authorizations
   and timestamps, observed reproduction package, and observed execution
   specification. `run_id` is domain-separated and derived from the plan plus
   both nonce contributions. A fourth timestamp fixes the start commitment.
6. The executor signs one terminal execution attestation. Success requires a
   zero exit status and one normalized result; failure requires a closed
   failure kind and no normalized result. The attestation binds the start,
   package, execution specification, output manifest, execution transcript,
   empty deviation manifest, declared interval, normalized-result digest, and
   executor-reported wall-clock, CPU-time, peak-RSS, and output-byte usage.
   A successful status requires every reported value to stay within the frozen
   ceiling; failed attempts retain their terminal negative evidence. A fifth
   timestamp covers the attestation.
7. The core recomputes the comparison. The submitted comparison must equal the
   core-derived value byte for byte. A sixth timestamp covers that comparison.
8. A distinct final-manifest key signs the entire chain and its terminal
   status. A seventh timestamp covers the signed final manifest.

Trusted-time intervals use exact microseconds from RFC 3161 `genTime` plus its
declared accuracy. Every predecessor's latest possible time must be strictly
earlier than the successor's earliest possible time. Overlap fails closed.
Declared millisecond times cannot establish order on their own.
The two `valid_until_ms` fields bound acceptance of that timestamped start
commitment only. They do not prove continued data-access authorization or that
the executor began processing before expiry. If governance requires an
execution-wide lease, operations must enforce and retain that lease, or a later
schema must add a separately trusted execution-start event.

## Trust and role separation

`aura.domain.independent_recomputation_trust_policy.v1` has five cryptographic
roles:

- evidence-custodian authorizer;
- independent-reproducer authorizer;
- executor for start and execution attestations;
- recomputation timestamp verifier;
- terminal manifest signer.

Every key identifier and Ed25519 public key must be distinct from every other
recomputation role and from all original preregistration, reviewer,
adjudicator, timestamp, and final-manifest roles. The independent reproducer
affiliation commitment must differ from every original reviewer affiliation.
The executor must carry that independent affiliation commitment; the custodian
must carry a different one. Commitments must refer to governed, randomly salted
records, not directly hash guessable organization names.

Signatures prove only that the corresponding trusted key signed the exact
claims. RFC 3161 receipts prove bounded document existence and order under the
configured TSA/PKIX/CRL assumptions. Neither mechanism proves the truth of an
affiliation, independence declaration, execution transcript, or governance
record.

## Deterministic result and terminal statuses

The only normalization profile in v1 is
`metrics_agreement_bits_outcome_v1`. It contains no raw messages or reviewer
identifiers. The validator returns one of:

- `aggregate_exact_match` — every normalized field equals the frozen original;
- `normalized_mismatch` — a structurally valid successful attempt differs;
- `execution_failed` — a structurally valid terminal failed attempt.

Mismatch and failure are retained as valid negative evidence. The stateless
attempt validator proves that the submitted bundle contains one terminal chain;
by itself it cannot prove that a sibling chain was never created, suppressed,
or selectively reported. The separate witnessed recomputation-attempt registry
binds the plan, run, and terminal evidence to an ordered append-only view. Any
retry must be registered under a new plan, new recomputation identity, new
nonce pair, and complete new signed and timestamped chain. See
[`domain-recomputation-attempt-registry.md`](./domain-recomputation-attempt-registry.md).

Registry validation establishes local integrity and state completeness only for
the submitted prefix through its witnessed checkpoint. It cannot discover
off-ledger execution or rule out competing successors or split views from one
snapshot. Operational acceptance still requires durable
pre-execution registration, external checkpoint publication, an independently
controlled WORM copy, and checkpoint comparison across observers.

Malformed schemas, unknown fields, broken signatures, substituted artifacts,
role-key reuse, ambiguous execution disposition, incomplete timestamp
materials, temporal overlap, privacy flags, or a caller-supplied comparison
that differs from the core result are validation errors rather than scientific
outcomes.

The strongest claim ceiling is
`independent_computational_reproduction_candidate`. The report always keeps
`scientific_replication_established`, `policy_activation_authorized`, and
`public_distribution_permitted` false. For Military, the original temporal
policy must remain disabled and `shadow_only`; for Kids, no report authorizes
disclosure of child or guardian material.

## Creating signatures and trusted-time receipts

Canonical typed claims can be signed with the closed five-kind adapter:

```sh
python3 ci/domain_recomputation_signer.py \
  --claims private/execution-claims.json \
  --kind execution_attestation \
  --private-key private/executor-key.pem \
  --key-id recomputation_executor \
  --output private/signed-execution.json
```

Accepted signer kinds are `custodian_authorization`,
`independent_reproducer_authorization`, `execution_start_commitment`,
`execution_attestation`, and `recomputation_final_manifest`. Plan and
comparison documents are not signed directly; their authorization/final
signatures and trusted timestamps bind them. The signer rejects all other
kinds and signs the exact compact claims bytes without reserializing them. The
claims must therefore use the exact field order emitted by the corresponding
Rust type; Rust parses and serializes the typed claims again before accepting
the signature.

For each of the seven subject kinds, first create a nonce-bearing request and
then verify the original response, selected chain, and full non-anchor CRL set:

```sh
python3 ci/domain_recomputation_timestamp_adapter.py request \
  --subject private/comparison.json \
  --policy-oid "$TSA_POLICY_OID" \
  --output private/comparison.tsq

python3 ci/domain_recomputation_timestamp_adapter.py verify-sign \
  --subject private/comparison.json \
  --subject-kind comparison_receipt \
  --request private/comparison.tsq \
  --response private/comparison.tsr \
  --ca-file private/tsa-roots.pem \
  --untrusted-chain private/tsa-chain.pem \
  --revocation-crl private/tsa-signer.crl.pem \
  --expected-policy-oid "$TSA_POLICY_OID" \
  --expected-tsa-spki-sha256 "$TSA_SPKI_SHA256" \
  --private-key private/timestamp-verifier-key.pem \
  --key-id recomputation_timestamp_verifier \
  --output private/comparison-timestamp.json \
  --require-pass
```

The timestamp adapter is a separate closed profile. Its seven subject kinds
are `recomputation_plan`, `evidence_custodian_authorization`,
`independent_reproducer_authorization`, `execution_start_commitment`,
`execution_attestation`, `comparison_receipt`, and
`recomputation_final_manifest`. It reuses the hardened RFC 3161 verifier,
immutable bounded input snapshots, private-key checks, and directory-bound
atomic output. The original DER request/response, exact signer-to-anchor DER
chain, and sorted complete CRL set must also be represented in the final
path-free timestamp-material inventory.

## Validation API

The shared entry point is
`validate_domain_study_independent_recomputation`. Kids and Military expose
domain-bound wrappers named `validate_independent_study_recomputation`. Each
call requires the original preregistration JSON, original result-evidence JSON,
private reproduction-manifest JSON, recomputation-evidence JSON, exact build
provenance and seed registry, original result trust policy, and separate
recomputation trust policy.

The registry overlay is validated by
`validate_domain_study_recomputation_registry`; Kids and Military expose
`validate_independent_study_recomputation_registry`. That call revalidates the
complete underlying study and recomputation chain, joins it to the witnessed
attempt-registration and terminal records, and proves append-only extension
relative to the required caller-retained typed accepted anchor. A successful
registry report is not proof of absence of off-ledger attempts, withheld views,
or equivocation among observers. Before relying on it, the caller must durably
compare-and-swap the returned complete next accepted anchor against the exact
reported previous-anchor digest.

The validator is a verifier of submitted cryptographic evidence, not a process
launcher. Resource values are signed executor observations, not measurements
made by this Rust verifier. Executing the plan, enforcing network/resource and
operating-system isolation, independently measuring usage, collecting the
private transcript and output manifest, durably operating and externally
witnessing the append-only registry, publishing checkpoints to independently
controlled storage, arranging truly independent custody, and retaining
ethics/consent/governance records are operational tasks outside this library.
