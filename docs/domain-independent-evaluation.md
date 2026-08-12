# Independent domain-evaluation contract

Status: protocol infrastructure implemented; independent evidence not yet
collected.

## Scope

The shared `aura-domain` contract preregisters message-level evaluation for
Kids and Military. It is separate from the more specialized Military temporal
review protocol. A valid preregistration declares and binds all of the
following for later trusted-time verification:

- the exact `DomainModuleEvidence`, including module version, state schema,
  lexical policy digest, and temporal policy digest;
- the exact Git revision, source tree, Cargo.lock, toolchain, target, profile,
  feature set, and evaluated binary digest;
- the fixed corpus digest, case count, inclusion and exclusion criteria, split
  discipline, label ontology, safe-boundary definition, minimum denominators,
  strata, and prospective sample-size rationale;
- attack families, exact variant count, per-family minimum, and construction
  manifest;
- two to five reviewers per case, distinct affiliations, independent
  adjudication, label blinding, label freeze, and agreement reporting;
- macro F1, per-threat recall, safe-boundary false-positive rate, and attack
  consistency as fixed primary outcomes, with nominal Krippendorff alpha fixed
  as the reviewer-agreement statistic and a fixed case-resampling BCa bootstrap
  plan for its 95% interval;
- no optional stopping, no imputation of incomplete review, separation of
  exploratory analyses, and complete reporting of exclusions and deviations.

Validation is fail-closed. A code, binary, policy-pack, state-schema, corpus,
criteria, ontology, safe-boundary, or attack-manifest change creates a different
study identity. Values in arrays that define hypotheses, features, threat
families, strata, attacks, or outcomes must be sorted and unique so semantically
equivalent documents do not acquire arbitrary orderings.

The bounded JSON v1 contract accepts 30 to 10,000 fixed cases. A larger study
requires a future streamed or chunked evidence schema rather than silently
exceeding the verifier's memory bound.

The declared `registered_at_ms` and boolean anti-bias fields are not trusted
proof that registration preceded label access. A canonical preregistration
must still be signed and independently timestamped before labels are released;
the later result gate must verify that chronology. Until that receipt exists,
the document is a reproducible commitment candidate, not a proven
preregistration event.

## Evidence ceiling

A successful validation does not produce a passing scientific result:

- repository seed and curated internal corpora return `engineering_only`;
- an admissible independent external corpus returns
  `independent_evidence_pending`;
- a known seed digest cannot be declared `independent_external`;
- the validator never asserts that reviewers are actually independent, that a
  sampling-frame declaration is true, or that construct validity has been
  established.

Those claims require controlled governance records, real frozen annotations,
adjudication, uncertainty analysis, and independent replication. Synthetic or
internally curated success remains engineering evidence even when every metric
is perfect.

## Domain bindings

Call the domain-owned entrypoint so the preregistration is checked against the
implementation that will actually run:

```rust
let kids = aura_kids::validate_independent_study_preregistration(
    preregistration_json,
    &actual_build_provenance,
    &additional_private_seed_digests,
)?;

let military = aura_military::validate_independent_study_preregistration(
    preregistration_json,
    &actual_build_provenance,
    &additional_private_seed_digests,
)?;
```

The validator always injects the committed repository data registry. Its single
embedded manifest covers every JSON artifact under workspace crate `data`
directories; the CI discovery test byte-verifies every manifest entry and fails
if a file is missing or drifts. The caller adds every private synthetic,
pilot-tuning, and prior evaluation digest. The preregistration must contain the
exact combined registry digest returned by
`domain_study_seed_registry_sha256`; omitting or adding a private seed later
invalidates the binding. This prevents exact corpus reuse, but transformed or
partially copied seed material still requires independent lineage auditing.

The corpus itself stays in the controlled research environment. The subsequent
machine-verifiable result chain is specified in
`docs/domain-independent-result-evidence.md`. Implementing that validator does
not mean an independent corpus has completed the protocol; a successful
preregistration binding alone remains `independent_evidence_pending`.

## Military temporal boundary

For a module with a temporal policy, the only admissible study mode is
`shadow_only`. Validation rejects the study if release evidence reports either
`runtime_enabled: true` or `action_execution_configured: true`. The study may
measure content-free temporal decisions, but it cannot enable a client or
server action. The existing packet-bound Military temporal protocol remains
the authoritative path for temporal human review, signatures, trusted
timestamps, receipt chains, and activation-readiness evidence.

## Next operational artifacts

The preregistration and result-chain contracts are ready; the following
governed inputs and real execution must exist before a confirmatory claim:

1. an independently governed sampling frame and dataset card;
2. ethics, consent, retention, and access-control records appropriate to each
   population;
3. frozen inclusion/exclusion criteria and an a-priori sample-size or precision
   analysis;
4. a difficult corpus with identity-disjoint splits, safe controls, and fixed
   attack variations;
5. a blinded review packet, independently timestamped reviewer decisions,
   signed assignment manifests, pre-adjudication agreement analysis, and
   separate adjudication;
6. a real execution of the fail-closed content-free result validator, including
   trusted preregistration-time verification and a signed evidence manifest
   tied to the exact preregistration, build, corpus, reviews, and policy.

Until those artifacts exist, this feature is research infrastructure, not a
claim of real-world effectiveness.
