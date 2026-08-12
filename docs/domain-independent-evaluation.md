# Independent domain-evaluation contract

Status: protocol infrastructure implemented; independent evidence not yet
collected.

## Scope

The shared `aura-domain` contract preregisters message-level evaluation for
Kids and Military. It is separate from the more specialized Military temporal
review protocol. A valid preregistration binds all of the following before
confirmatory labels are inspected:

- the exact `DomainModuleEvidence`, including module version, state schema,
  lexical policy digest, and temporal policy digest;
- the fixed corpus digest, case count, inclusion and exclusion criteria, split
  discipline, strata, and prospective sample-size rationale;
- attack families, exact variant count, per-family minimum, and construction
  manifest;
- two to five reviewers per case, distinct affiliations, independent
  adjudication, label blinding, label freeze, and agreement reporting;
- macro F1, per-threat recall, safe-boundary false-positive rate, and attack
  consistency as fixed primary outcomes;
- no optional stopping, no imputation of incomplete review, separation of
  exploratory analyses, and complete reporting of exclusions and deviations.

Validation is fail-closed. A policy-pack, state-schema, corpus, criteria, or
attack-manifest change creates a different study identity. Values in arrays
that define hypotheses, strata, attacks, or outcomes must be sorted and unique
so semantically equivalent documents do not acquire arbitrary orderings.

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
    &known_seed_digests,
)?;

let military = aura_military::validate_independent_study_preregistration(
    preregistration_json,
    &known_seed_digests,
)?;
```

The caller must enumerate every repository, synthetic, pilot-tuning, and prior
evaluation corpus digest in `known_seed_digests`. The corpus itself stays in
the controlled research environment; public and release evidence contains
only the bound digest and aggregate results.

## Military temporal boundary

For a module with a temporal policy, the only admissible study mode is
`shadow_only`. Validation rejects the study if release evidence reports either
`runtime_enabled: true` or `action_execution_configured: true`. The study may
measure content-free temporal decisions, but it cannot enable a client or
server action. The existing packet-bound Military temporal protocol remains
the authoritative path for temporal human review, signatures, trusted
timestamps, receipt chains, and activation-readiness evidence.

## Next operational artifacts

The code contract is ready; the following inputs must be produced outside the
implementation team before a confirmatory run:

1. an independently governed sampling frame and dataset card;
2. ethics, consent, retention, and access-control records appropriate to each
   population;
3. frozen inclusion/exclusion criteria and an a-priori sample-size or precision
   analysis;
4. a difficult corpus with identity-disjoint splits, safe controls, and fixed
   attack variations;
5. a blinded review packet, independently timestamped reviewer decisions, and
   separate adjudication;
6. a content-free result bundle and signed evidence manifest tied to the exact
   preregistration and policy evidence.

Until those artifacts exist, this feature is research infrastructure, not a
claim of real-world effectiveness.
