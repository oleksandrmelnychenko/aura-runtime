# Recomputation-attempt registry and witnessed checkpoints

The recomputation-attempt registry is the selective-reporting control that
surrounds `aura.domain.independent_recomputation_evidence.v1`. The existing
recomputation bundle validates one submitted terminal attempt. The registry
adds a signed, sequenced, hash-chained view of attempt registration and its
terminal outcome, followed by a separately witnessed checkpoint.

This contract narrows one evidentiary gap; it does not turn computational
reproduction into scientific replication. An exact aggregate match still means
only that the frozen aggregates were reproduced from the same private package
under the declared computation. It is not evidence from a new sample,
population, labeling process, intervention, or implementation.

## Claim boundary

A successful validation establishes all of the following:

- the submitted registry view is internally ordered and hash-chain consistent;
- every record in that view is signed by the configured registry operator;
- the target recomputation follows the closed
  `attempt_registered -> attempt_terminal` state transition and its identifiers
  and digests match the independently validated recomputation bundle;
- the checkpoint commits to the submitted entry count and chain head and is
  signed by both the registry operator and a distinct checkpoint witness;
- relative to the required previously accepted typed anchor, the new view is an
  exact append-only extension rather than a rollback, truncation, or rewrite
  of the previously accepted prefix.

That is **local integrity and state completeness of the submitted prefix through
the witnessed checkpoint**. The checkpoint reports its exact pending-attempt count;
it does not relabel a still-open registration as a terminal attempt. Prefix
completeness does not prove that an attempt performed outside the governed
workflow was registered, that an operator did not withhold a view, or that two
observers were not shown competing valid successors to the same anchor. The
strict validator starts from an explicitly accepted genesis or predecessor
checkpoint; accepting that initial anchor is still a governance trust decision.
Cryptographic validation of one view cannot, by itself, establish global
non-equivocation.

The validator reruns the complete evidence chain only for the target terminal
attempt supplied to the API. Terminal statuses for unrelated entries in the
same prefix remain signed registry-operator assertions unless their own
recomputation bundles are validated separately. The report therefore marks
only the target terminal as core-verified.

Operational scientific reliance therefore requires checkpoint publication to
an independently controlled write-once/read-many (WORM) store or equivalent
transparency service, retention by the independent witness, and comparison of
checkpoints across observers. Witness operation, checkpoint dissemination,
gossip or cross-monitoring, availability monitoring, and investigation of
missing terminal records remain outside the stateless Rust validator.

## Closed record state machine

The closed v1 identifiers are:

- trust policy:
  `aura.domain.recomputation_attempt_registry_trust_policy.v1`;
- evidence bundle: `aura.domain.recomputation_attempt_registry_evidence.v1`;
- entry: `aura.domain.recomputation_attempt_registry_entry.v1`;
- checkpoint claims:
  `aura.domain.recomputation_attempt_registry_checkpoint.v1`;
- accepted anchor:
  `aura.domain.recomputation_attempt_registry_accepted_anchor.v1`;
- checkpoint timestamp verification:
  `aura.domain.recomputation_attempt_registry_timestamp_verification.v1`.

The registry uses two semantic record kinds for each recomputation identity:

1. `attempt_registered` binds the intended recomputation attempt to its exact
   plan digest and plan-timestamp digest, both signed authorization and
   authorization-timestamp digests, derived `run_id`, and declared terminal
   deadline. The contract models registration before the external runner is
   permitted to start, but the final checkpoint alone does not prove that
   wall-clock order.
2. `attempt_terminal` binds the registered attempt to its terminal
   recomputation-evidence digest, final-manifest digest, and declared outcome.
   The validator revalidates and derives those values for the API's target
   attempt only; terminal claims for unrelated entries remain operator-signed
   assertions until validated with their own evidence bundles.

Every record also binds the registry identity, a contiguous sequence number,
and the previous record digest. The first record uses the contract's fixed
genesis rule. Reordering, deletion, insertion, sequence gaps, a wrong
predecessor, duplicate registration, a terminal without registration, more
than one terminal outcome, or another transition for the same attempt after
its terminal record fails closed.

The registry writer must atomically and durably commit an appended entry, its
new chain head, and every uniqueness index before exposing success or signing a
checkpoint over that state. A crash must leave either the complete old state or
the complete new state. Updating the entry bytes without the head or uniqueness
state, signing an uncommitted head, or rebuilding uniqueness from a partial
write can admit duplicate or selectively lost attempts and is outside the
validator's guarantees.

The v1 verifier accepts at most 4,096 entries and 16 MiB of registry JSON in one
full submitted prefix. Reaching that bound requires a separately governed,
externally anchored successor registry; silently resetting sequence zero or
discarding the old checkpoint is not rollover.

Failures and normalized mismatches are terminal scientific evidence, not
erasable operational errors. A retry requires a new plan, recomputation
identity, nonce pair, `run_id`, and full signed and timestamped chain. The new
attempt must be registered before access or execution begins. Operations must
deny execution when durable registration is unavailable; accepting a later
backfilled record would reintroduce the selective-reporting path the registry
is intended to constrain.

## Trusted time and the pre-execution boundary

V1 applies RFC 3161 trusted time to the complete witnessed checkpoint, not to
each registry entry. The checkpoint's accuracy-adjusted trusted-time interval
must be strictly later than the recomputation final-manifest interval. This
proves that the complete submitted view existed no later than the checkpoint's
trusted interval under the selected TSA, PKIX, revocation, and retained-material
assumptions.

The report separates two deadline statements. The field
`target_terminal_within_operator_declared_deadline` compares the signed
operator-declared append time with `terminal_due_at_ms`; it is not independently
trusted. `terminal_deadline_compliance_proven` is true only when the latest
possible time in the checkpoint's RFC 3161 interval is no later than the
inclusive end of the deadline millisecond (`terminal_due_at_ms * 1000 + 999`
microseconds). If that latest trusted time is later, the outcome is
**unknown**, not a cryptographically proved miss: the terminal entry may have
existed before the deadline even though the later checkpoint cannot establish
it. The checkpoint's declared `completed_at_ms` must be no later than the
earliest possible time in its trusted interval; it cannot borrow the interval's
latest bound to place an untrusted declaration earlier.

One final checkpoint does **not** cryptographically prove when the individual
registration entry was appended. In particular, the current recomputation
bundle does not bind an inclusion receipt and the overlay cannot prove by
itself that registration preceded execution. That is a mandatory operational
admission control in v1: the future runner must deny execution until it confirms
a durable append and must retain its independent admission evidence. A future
contract would need a separately timestamped and witnessed phase checkpoint or
trusted inclusion receipt to make that pre-start gate independently verifiable
from registry evidence alone.

Trusted time also does not prove when computation actually began, that
execution matched the signed transcript, or that governance declarations are
true.

## Creating signatures and the checkpoint timestamp

Use the closed registry signer for the entry, operator checkpoint, and witness
checkpoint envelopes. It signs the exact compact typed claims bytes and rejects
other kinds:

```sh
python3 ci/domain_recomputation_registry_signer.py \
  --claims private/registry-entry-claims.json \
  --kind registry_entry \
  --private-key private/registry-operator-key.pem \
  --key-id recomputation_registry_operator \
  --output private/signed-registry-entry.json
```

The accepted signer kinds are `registry_entry`,
`registry_checkpoint_operator`, and `registry_checkpoint_witness`. Operator and
witness checkpoint signatures cover the same exact checkpoint claims with
different domain separators and distinct keys.

Only the fully signed checkpoint is submitted for RFC 3161 trusted time:

```sh
python3 ci/domain_recomputation_registry_timestamp_adapter.py request \
  --subject private/signed-registry-checkpoint.json \
  --policy-oid "$TSA_POLICY_OID" \
  --output private/registry-checkpoint.tsq

python3 ci/domain_recomputation_registry_timestamp_adapter.py verify-sign \
  --subject private/signed-registry-checkpoint.json \
  --subject-kind registry_checkpoint \
  --request private/registry-checkpoint.tsq \
  --response private/registry-checkpoint.tsr \
  --ca-file private/tsa-roots.pem \
  --untrusted-chain private/tsa-chain.pem \
  --revocation-crl private/tsa-signer.crl.pem \
  --expected-policy-oid "$TSA_POLICY_OID" \
  --expected-tsa-spki-sha256 "$TSA_SPKI_SHA256" \
  --private-key private/registry-timestamp-verifier-key.pem \
  --key-id recomputation_registry_timestamp_verifier \
  --output private/registry-checkpoint-timestamp.json \
  --require-pass
```

The adapter accepts only `registry_checkpoint`. The original DER request and
response, exact signer-to-anchor certificate path, and complete sorted CRL set
must be retained and represented in the evidence material inventory.

## Trust separation

The registry trust policy has three dedicated cryptographic roles:

- registry-record and checkpoint operator;
- independent checkpoint witness;
- registry timestamp verifier.

Their key identifiers and Ed25519 public keys must be pairwise distinct and
must not reuse any original-study or recomputation role. The witness signature
shows that the configured witness signed the checkpoint; organizational
independence and reliable external retention are governance facts that require
separate evidence.

V1 fixes all three keys for one `registry_id` and defines no in-log key
transition. A key change therefore fails closed. Recovery or rotation requires
a separately governed new registry anchor, or a future schema that explicitly
binds a witnessed key-transition record; silently substituting a key in an
existing registry is never accepted.

The checkpoint binds the registry identity, exact entry count, chain-head
digest, domain-framed aggregate of the ordered signed-entry digests, prior
accepted-anchor digest, prior checkpoint count/head/aggregate, and
pending-attempt count. The typed accepted anchor is either an explicitly
approved empty `genesis` anchor or a `witnessed` anchor that retains the complete
signed checkpoint and its trusted-time receipt. This lets the next validation
reverify predecessor signatures and trusted chronology instead of trusting
caller-supplied claims alone.

The validator returns that witnessed state as `next_accepted_anchor`, together
with `previous_accepted_anchor_sha256` and `next_accepted_anchor_sha256` under a
separate domain-framed digest. Before relying on the report or accepting another
extension, the caller must compare-and-swap the stored anchor from the exact
reported previous digest to the exact reported next digest and durably persist
the complete next anchor. A failed or racing CAS invalidates operational
reliance on that report. Merely retaining checkpoint claims, or storing the new
anchor after downstream use, reopens rollback and competing-successor windows.

## Validation API

The shared Rust entry point is
`validate_domain_study_recomputation_registry`. Kids and Military expose the
domain-bound wrapper `validate_independent_study_recomputation_registry`.
Validation takes the original preregistration, result evidence, private
reproduction manifest, recomputation evidence, registry evidence, exact domain
policy evidence and build provenance, complete seed registry, the three trust
policies, and a required previously accepted typed anchor. Genesis acceptance is
represented by the typed anchor returned from
`domain_study_recomputation_registry_genesis_checkpoint`; normal validation
never silently treats an absent predecessor or bare checkpoint claims as
trusted. Subsequent calls must pass the complete witnessed accepted anchor
returned by the previous validated report.

The complete original and recomputation validators run again before registry
records are joined. The registry cannot be used to bless an invalid underlying
study chain. The returned report is content-free and records the validated
checkpoint and core-derived status; it never authorizes policy activation,
private-data disclosure, or public distribution.

Validation is read-only: returning `next_accepted_anchor` does not persist it,
advance an operational registry, or make a report safe to act on. The host owns
the durable compare-and-swap step and must treat validation plus failed anchor
persistence as an unaccepted transition.

For Military, temporal actions remain disabled and shadow-only. For Kids, no
registry status authorizes disclosure of child, guardian, or conversation
content.

## Operational acceptance checklist

Before relying on a checkpoint for confirmatory reporting, operators must:

- make durable attempt registration a prerequisite for execution;
- atomically durably commit each entry, chain head, and uniqueness state before
  acknowledging the append or signing a checkpoint;
- append failure and mismatch outcomes as faithfully as exact matches;
- require terminal closure or formally investigate every open registered run;
- export each witnessed checkpoint to an independently controlled WORM target;
- CAS-persist the complete `next_accepted_anchor` against the reported previous
  anchor digest before relying on the report;
- retain accepted anchors outside operator control;
- compare checkpoint count and head across independent observers;
- preserve RFC 3161 requests, responses, certificate paths, CRLs, signatures,
  governance records, and the private evidence package under approved access;
- document registry outages, rejected appends, witness unavailability, fail-closed
  key-compromise handling, separately governed re-anchoring, recovery, and any
  exceptional execution denial.

Passing the validator without these controls is useful engineering evidence,
but it is not proof that all real-world recomputation attempts were disclosed.
