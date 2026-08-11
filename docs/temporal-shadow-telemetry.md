# Temporal Shadow telemetry for on-prem and ADK hosts

The temporal Shadow telemetry API evaluates the disabled military temporal
policy without exposing its output as a client or server action. It is built
with the `shadow-telemetry` Cargo feature and is not part of the default mobile
runtime feature set.

## Safety boundary

- The ordinary temporal runtime policy remains disabled.
- The collector never returns a `DomainTemporalOutput` to its caller.
- Any action produced by a future policy is counted as suppressed and makes the
  validation report fail; action execution is always reported as `false`.
- Inputs contain no message text. They may contain process-local actor numbers
  and content hashes needed for inference, but neither is retained or exported.
- The collector stores counters and latency buckets only. It stores no input,
  event, actor, conversation, or per-case record.
- Export is refused below 20 observations as a minimum cohort floor. This is a
  data-minimization control, not differential privacy or a proof of anonymity;
  deployments that need stronger disclosure protection must add approved
  suppression or noise rules before exporting aggregates.

## Batch adapter

The batch input has schema
`aura.military.temporal_shadow_input.v1`, a deployment value of `on_prem` or
`adk`, a reporting window, and 20 to 100,000 `DomainTemporalInput` objects.
Each input is limited to 500 events. The reporting period must be between one
hour and 31 days, and every `as_of_ms` must fall inside it.

The source batch stays inside the deployment boundary and must not be uploaded
as release evidence. Only the aggregate output may leave that boundary.

```sh
cargo run --locked -p aura-military --features shadow-telemetry \
  --example temporal_shadow_telemetry -- \
  --input /protected/local/temporal-shadow-batch.json \
  --output artifacts/temporal-shadow-aggregate.json \
  --require-pass
```

The release gate separately replays the content-free seed corpus through both
deployment adapters and writes
`artifacts/temporal-shadow-telemetry-validation.json`. That artifact proves the
privacy and no-action invariants of the adapters; it is not a substitute for
deployment measurements.

## Operational period analysis

Compare reports only when deployment type, policy artifact, reporting duration,
and sampling rules are identical. Track at minimum:

- evaluated inputs and source-event volume;
- inputs with and without temporal signals;
- counts by non-content reason code;
- multi-signal inputs;
- coarse latency distribution;
- suppressed action count, which must remain zero.

Do not add raw examples, actor pseudonyms, conversation identifiers, content
hashes, or per-conversation traces to this report. Complex-case investigation
belongs in a separately authorized, access-controlled review process.
