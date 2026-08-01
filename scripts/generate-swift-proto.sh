#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proto_file="$repo_root/proto/aura/messenger/v1/messenger.proto"
output_root="$repo_root/swift/Sources/AuraAgent"
generated_file="$output_root/aura/messenger/v1/messenger.pb.swift"
expected_generator_version="1.38.1"
mode="${1:---write}"

if [[ "$mode" != "--write" && "$mode" != "--check" ]]; then
    echo "usage: $0 [--write|--check]" >&2
    exit 2
fi

command -v protoc >/dev/null || {
    echo "protoc is required" >&2
    exit 1
}
command -v protoc-gen-swift >/dev/null || {
    echo "protoc-gen-swift is required" >&2
    exit 1
}

generator_version="$(protoc-gen-swift --version)"
if [[ "$generator_version" != "protoc-gen-swift $expected_generator_version" ]]; then
    echo "expected protoc-gen-swift $expected_generator_version, got: $generator_version" >&2
    exit 1
fi

if [[ "$mode" == "--write" ]]; then
    mkdir -p "$(dirname "$generated_file")"
    protoc \
        --proto_path="$repo_root/proto" \
        --swift_opt=Visibility=Public \
        --swift_out="$output_root" \
        "$proto_file"
    exit 0
fi

temporary_root="$(mktemp -d)"
trap 'rm -rf "$temporary_root"' EXIT
protoc \
    --proto_path="$repo_root/proto" \
    --swift_opt=Visibility=Public \
    --swift_out="$temporary_root" \
    "$proto_file"

if ! cmp -s \
    "$temporary_root/aura/messenger/v1/messenger.pb.swift" \
    "$generated_file"; then
    echo "generated Swift protobuf is stale; run: just swift-proto-generate" >&2
    exit 1
fi

echo "Swift protobuf source is current (protoc-gen-swift $expected_generator_version)."
