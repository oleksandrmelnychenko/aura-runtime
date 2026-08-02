#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test_name="analysis_is_fast"
test_listing="$(cargo test --release -p aura-core --lib -- --ignored --list)"
match_count="$(grep -F -c "${test_name}: test" <<<"$test_listing" || true)"
if [[ "$match_count" -ne 1 ]]; then
  echo "error: expected exactly one ignored test named ${test_name}, found ${match_count}" >&2
  exit 1
fi
full_test_name="$(grep -F "${test_name}: test" <<<"$test_listing")"
full_test_name="${full_test_name%: test}"
cargo test --release -p aura-core --lib "$full_test_name" -- --ignored --exact --nocapture
