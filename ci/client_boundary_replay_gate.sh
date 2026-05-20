#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p aura-agent-ffi ffi_replays_six_month_world_across_periodic_state_restore -- --ignored --nocapture
cargo test -p aura-agent-ffi ffi_replays_dense_two_year_world_across_periodic_state_restore -- --ignored --nocapture
