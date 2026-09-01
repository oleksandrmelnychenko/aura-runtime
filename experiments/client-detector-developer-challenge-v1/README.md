# Client detector developer challenge v1

This experiment is a frozen, developer-authored semantic challenge for the
client-side detector. It contains 240 counterfactual pairs: 10 pairs for each
of 8 threat families in English, Ukrainian, and Russian (480 conversations).

Each pair keeps the target phrase and account metadata fixed. The risky member
uses the phrase as an active intent or request. The safe member repeats the
exact phrase inside a closed quotation and adds an explicit reporting,
refusal, educational, or supportive stance. This isolates contextual handling
from simple keyword presence.

Build and freeze the corpus before any detector run:

```sh
python3 training/developer_challenge.py build \
  --protocol experiments/client-detector-developer-challenge-v1/protocol.json \
  --scenario-bank experiments/client-detector-developer-challenge-v1/scenario-bank.json \
  --output-dir artifacts/developer-challenge-v1
```

Then build the conversation probe and evaluate the exact frozen corpus:

```sh
cargo build --release -p aura-core --example client_detector_conversation_probe
python3 training/developer_challenge.py evaluate \
  --manifest artifacts/developer-challenge-v1/manifest.json \
  --protocol experiments/client-detector-developer-challenge-v1/protocol.json \
  --scenario-bank experiments/client-detector-developer-challenge-v1/scenario-bank.json \
  --cases artifacts/developer-challenge-v1/cases.jsonl \
  --gold artifacts/developer-challenge-v1/gold.jsonl \
  --probe target/release/examples/client_detector_conversation_probe \
  --output artifacts/developer-challenge-v1/result.json
```

The result contains aggregate metrics and failed case IDs, never conversation
plaintext. `diagnostic_pass` means only that this authored challenge met its
prespecified targets. It is not release certification and cannot replace the
internal blinded holdout.
