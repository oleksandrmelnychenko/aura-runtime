#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test_names=(
  ffi_replays_six_month_world_across_periodic_state_restore
  ffi_replays_dense_two_year_world_across_periodic_state_restore
)
test_listing="$(cargo test -p aura-agent-ffi -- --ignored --list)"

for test_name in "${test_names[@]}"; do
  match_count="$(grep -F -c "${test_name}: test" <<<"$test_listing" || true)"
  if [[ "$match_count" -ne 1 ]]; then
    echo "error: expected exactly one ignored test named ${test_name}, found ${match_count}" >&2
    exit 1
  fi
  full_test_name="$(grep -F "${test_name}: test" <<<"$test_listing")"
  full_test_name="${full_test_name%: test}"
  cargo test -p aura-agent-ffi "$full_test_name" -- --ignored --exact --nocapture
done
