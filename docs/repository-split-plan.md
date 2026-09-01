# AURA repository split

## Decision

AURA is split into two independently released Git repositories:

- `aura-runtime` — the client safety runtime and Apple integration;
- `aura-replay` — the server-side Relay library and its deployment adapters.

The existing repository history becomes `aura-runtime`. The rename is performed only after its
current changes are stabilized so the XCFramework, Swift package, release manifest, and Aura
Messenger trust paths can be updated and verified as one reviewed operation.

Neither repository uses a public `V1` suffix in product, module, or type names. Version numbers
remain only in serialized wire namespaces and compatibility metadata where they are required for
safe evolution.

## Client repository boundary

The client repository owns all code required to produce a local safety decision without a network
connection:

- `aura-runtime`
- `aura-agent-ffi`
- `aura-agent-policy`
- `aura-contracts`, excluding Relay request, response, transport, and authentication types
- `aura-core`
- `aura-domain`
- `aura-kids`
- `aura-military`
- `aura-ml`
- `aura-patterns`
- `aura-proto`
- the C header, Swift wrapper, Apple artifact builder, local evaluation suites, and client datasets

The client library may produce an explicitly privacy-reduced export value. It does not open
sockets, select HTTP endpoints, perform retries, hold server credentials, or decide how a value is
transported. Aura Messenger owns transport and provisioning at the application boundary.

## Server repository boundary

The server repository owns Relay processing and deployment integration:

- `aura-relay-api`
- `aura-relay-context`
- `aura-relay-inference`
- `aura-relay-intake`
- `aura-relay-ml`
- `aura-relay-observability`
- `aura-relay-policy`
- `aura-relay-risk`
- `aura-relay-store`
- `aura-wire-relay`
- a server-owned `aura-relay-contracts` crate extracted from the current Relay module
- server authentication, replay protection, rate limiting, persistence, metrics, and deployment
  adapters

The server repository must not contain the Swift wrapper, C ABI, XCFramework builder, client
lexicons, client evaluation corpora, or application UI.

## Contract ownership

There is no editable copy of the same contract in both repositories.

The client repository owns the stable safety vocabulary used by the local detector, such as threat
types, observations, context frames, and client decisions. The server repository consumes the
small required subset as an exact Git revision or released package.

The server repository owns Relay envelopes, authentication fields, replay metadata, and response
types. If Aura Messenger later sends an approved privacy-reduced client signal to Relay, the app
uses the server's generated transport contract and maps an explicit client export into it. The
client detector itself remains unaware of the server and transport.

The existing messenger protobuf used by the C ABI stays client-internal. It is not reused as a
server API wholesale.

## Dependency direction

```text
Aura Messenger
    ├── pinned client artifact from aura-runtime
    └── application-owned provisioning and transport

aura-replay
    └── pinned client vocabulary package, only if shared semantic types are required

aura-runtime
    └── no dependency on aura-replay
```

The dependency is one-way. A client release never waits for, imports, or links the server
implementation.

## History-preserving migration

1. Stabilize the current dirty client work into reviewed, scoped commits. Do not stage the entire
   worktree as one change.
2. Record a reproducible baseline: workspace tests, client artifact digest, protobuf compatibility,
   and the current server package tests.
3. Rename the existing repository to `aura-runtime`, preserving its full history and release tags.
4. Create `aura-replay` from a history-preserving filtered branch of this repository. Do
   not copy files into a fresh repository by hand.
5. In the server repository, extract `relay.rs` into `aura-relay-contracts` and replace dependencies
   on client-only modules with the pinned minimal vocabulary package.
6. Make the server workspace build and pass its tests independently.
7. Remove Relay crates and the Relay release profile from the client repository.
8. Make the client workspace and Apple artifact build pass independently. Verify the rebuilt
   artifact and update its accepted digest through the normal review gate.
9. Point CI, ownership rules, dependency scanning, and release automation at the appropriate
   repository.
10. Delete temporary migration branches only after both repositories reproduce the baseline and
   Aura Messenger consumes the reviewed client artifact.

## Required gates

The split is complete only when all of the following are independently true:

- the client workspace contains no Relay, HTTP, server persistence, or server runtime dependency;
- the client offline detector and language/compositional evaluation suites pass;
- the client C ABI, protobuf compatibility, Swift wrapper, and XCFramework build pass;
- the server workspace builds without the client source tree present;
- Relay authentication, replay, privacy, inference, risk, persistence, and wire tests pass;
- compatibility checks pin exact contract revisions and reject an unreviewed contract change;
- Aura Messenger accepts the newly reviewed client artifact digest on both target devices.

## Non-goals

- The repository split does not introduce a new HTTP/JSON client layer.
- It does not move Aura Messenger networking into the client detector library.
- It does not create a third shared-contract repository unless two-repository ownership proves
  insufficient after the first independent releases.
- It does not rename stable public client APIs solely to reflect the repository split.
