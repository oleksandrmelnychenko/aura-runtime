#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

input="${1:-crates/aura-core/data/safety_world_v2_schema.example.json}"
python_bin="${PYTHON:-python3}"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aura-safety-world-v2.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

projected="$tmpdir/safety_world_v2_projected_world_sim.json"
platform_seed="$tmpdir/safety_world_v2_platform_seed.json"

cargo fmt -p aura-core --check
cargo test -p aura-core --example safety_world_v2_project
cargo test -p aura-core --example safety_world_v2_platform_seed

cargo run -p aura-core --example safety_world_v2_validate -- \
  --input "$input"

cargo run -p aura-core --example safety_world_v2_project -- \
  --input "$input" \
  --output "$projected"

cargo run -p aura-core --example world_sim -- \
  --input "$projected" \
  --summary-only \
  --require-clean

cargo run -p aura-core --example safety_world_v2_platform_seed -- \
  --input "$input" \
  --output "$platform_seed"

"$python_bin" - "$platform_seed" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
seed = json.loads(path.read_text(encoding="utf-8"))

if seed.get("schema_version") != "platform_seed.v1":
    raise SystemExit("platform seed schema_version mismatch")

events = seed.get("events")
if not isinstance(events, list) or not events:
    raise SystemExit("platform seed exported no events")

for event in events:
    content = event.get("content")
    if not isinstance(content, dict):
        raise SystemExit(f"event {event.get('id')} missing content object")

    visibility = event.get("visibility")
    mode = content.get("mode")
    if visibility in {"private", "guardian_visible", "members", "followers"}:
        if mode != "opaque_fixture_ref":
            raise SystemExit(
                f"event {event.get('id')} with visibility {visibility} leaked mode {mode}"
            )
        if "text" in content:
            raise SystemExit(f"event {event.get('id')} leaked private plaintext")
    elif visibility in {"public", "moderators_only"}:
        if mode != "plaintext":
            raise SystemExit(
                f"event {event.get('id')} with visibility {visibility} expected plaintext"
            )
PY

if grep -Eq "Don't tell your parents|Send me a photo" "$platform_seed"; then
  echo "private fixture text leaked into platform seed" >&2
  exit 1
fi

echo "Safety World v2 smoke passed: $input"
