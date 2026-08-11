# AURA Core Research Evidence Roadmap

Status: prospective research track, recorded July 25, 2026.

## Purpose

AURA Core is intended to support a future doctoral research program in
addition to its production role. The current release, replay, boundary, and
artifact gates are research infrastructure; they are not, by themselves,
evidence for a scientific claim.

Production readiness and research validity remain separate:

- production gates ask whether the current runtime is safe and compatible
  enough to ship;
- research protocols ask whether a stated mechanism causes a measurable,
  reproducible improvement over defined baselines.

No production threshold, pilot observation, or synthetic scenario should be
presented as a doctoral result without a versioned protocol and an appropriate
statistical analysis.

## Candidate Research Questions

1. Does typed longitudinal context improve safety detection and calibration
   relative to stateless message analysis?
2. Do explicit counterfactual boundaries reduce false escalation on supportive,
   counterspeech, trusted-adult, peer-banter, and OPSEC-warning messages?
3. Which memory components improve time-to-detection without accumulating
   cross-conversation contamination?
4. Do domain-owned KIDS and MILITARY policies outperform a single shared policy
   while preserving a stable core contract?
5. How do accuracy, calibration, latency, and memory scale across long-horizon
   conversations and account profiles?

These are candidate questions only. Final hypotheses, primary outcomes, and
exclusion rules should be preregistered before confirmatory evaluation.

## Required Experimental Baselines and Ablations

At minimum, controlled evaluation should compare:

- stateless message-only analysis;
- typed context with memory disabled;
- typed context without relationship/profile conditioning;
- typed context without protective-factor interpretation;
- typed context without domain-specific policy packs;
- rules fallback versus a governed model-backed runtime when the ONNX bundle is
  available;
- uninterrupted execution versus export/import restart continuation.

Each ablation must use the same immutable evaluation split and artifact
identity. Changes to code, rules, datasets, thresholds, or model bundles create
a new experiment identity.

## Outcome Families

Report more than a single accuracy score:

- precision, recall, F1, and precision-recall curves by threat family;
- Brier score and Expected Calibration Error;
- safe-boundary false-positive and false-escalation rates;
- time-to-detection and pre-onset detection;
- counterfactual consistency and restart equivalence;
- subgroup results by language, age band, relationship, account type, domain,
  and profile;
- latency, maximum RSS, retained context size, and throughput;
- human-review disagreement for high-stakes boundary cases.

Report confidence intervals and effect sizes. Repeated runs must use declared
seeds where randomness exists. Deterministic components should produce exact
replays, not merely statistically similar outputs.

## Dataset and Leakage Discipline

- Version every dataset and record its SHA-256 digest.
- Split by conversation, participant identity, and time where appropriate;
  never allow turns from one trajectory to leak across train/tune/test.
- Keep exploratory and confirmatory test sets distinct.
- Record source family, review status, language, age band, relationship, and
  consent/governance metadata.
- Treat synthetic, curated, pilot, and real-world datasets as different
  evidence classes.
- Never tune rules or thresholds against the final confirmatory test set.
- Keep raw child or guardian text out of release and research evidence bundles
  unless a separately approved protocol explicitly permits it.

## Reproducibility Contract

Every reported experiment should bind:

- Git revision and deterministic `source_tree_sha256`;
- Cargo.lock, Rust toolchain, target triples, Cargo profile, and feature set;
- runtime, wire, persisted-state, and FFI contract versions;
- rule-pack, dataset, model-manifest, trust-keyring, and binary hashes;
- exact command, environment profile, seed set, and hardware class;
- normalized machine-readable results and analysis code.

The Apple artifact manifest and
`aura.apple_artifact_verification.v1` report establish the binary provenance
part of this contract. A dirty artifact may support local exploration but is
never a shippable or confirmatory research artifact.

Temporal confirmatory review additionally uses a domain-separated Ed25519
attestation over the preregistration/corpus/packet commitment. This authenticates
the institutional signer and detects substitution, but it is not a trusted time
source. The RFC 3161 verification contract now binds the exact commitment to an
expected timestamp policy, certificate chain, nonce, and pinned TSA signer, and
requires the `genTime + accuracy` upper bound before the earliest declared
review completion. The remaining
research limit is explicit: review completion times are bundle-declared until
individual signed submission receipts are independently timestamped.

## Evidence Maturity

1. **Engineering evidence** — unit, property, boundary, replay, compatibility,
   and performance gates.
2. **Pilot evidence** — privacy-safe shadow data plus documented human review.
3. **Exploratory research** — versioned analyses used to refine hypotheses.
4. **Confirmatory research** — preregistered protocol, frozen test data,
   statistical analysis, and independent reproducibility material.

Claims must name their evidence maturity. Movement to a higher level requires
new evidence; it is not an automatic consequence of passing the previous
level.

## Planned Research Artifacts

Future research work should introduce versioned, reviewable locations for:

- protocols and preregistrations;
- dataset cards and consent/governance records;
- hypothesis and outcome schemas;
- ablation configurations;
- statistical analysis scripts and environment locks;
- experiment manifests and normalized result bundles;
- threat-to-validity and ethics review notes.

These additions belong to a separate research milestone after the core
refactor and release artifact are complete.
