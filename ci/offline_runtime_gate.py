#!/usr/bin/env python3

"""Fail when the client runtime gains an HTTP client or socket transport."""

import json
import re
import subprocess
import sys
from pathlib import Path


FORBIDDEN_NETWORK_PACKAGES = frozenset(
    {
        "http",
        "http-body",
        "http-body-util",
        "httparse",
        "hyper-rustls",
        "hyper-tls",
        "hyper",
        "hyper-util",
        "isahc",
        "native-tls",
        "reqwest",
        "rustls",
        "rustls-native-certs",
        "rustls-pemfile",
        "rustls-pki-types",
        "surf",
        "tokio-native-tls",
        "tokio-rustls",
        "tower-http",
        "ureq",
        "ureq-proto",
        "webpki-roots",
    }
)
FORBIDDEN_SOURCE_PATTERNS = (
    re.compile(r"\b(?:reqwest|ureq|hyper)::"),
    re.compile(r"\b(?:TcpListener|TcpStream|ToSocketAddrs|UdpSocket)\b"),
    re.compile(r"\b(?:tokio|async_std)::net::"),
)


def resolved_package_names(metadata: dict) -> set[str]:
    package_by_id = {
        package["id"]: package["name"] for package in metadata.get("packages", [])
    }
    resolve = metadata.get("resolve") or {}
    return {
        package_by_id[node["id"]]
        for node in resolve.get("nodes", [])
        if node.get("id") in package_by_id
    }


def forbidden_packages(metadata: dict) -> list[str]:
    return sorted(resolved_package_names(metadata) & FORBIDDEN_NETWORK_PACKAGES)


def forbidden_source_matches(source: str) -> list[str]:
    return [pattern.pattern for pattern in FORBIDDEN_SOURCE_PATTERNS if pattern.search(source)]


def load_metadata(repo_root: Path) -> dict:
    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--locked",
            "--offline",
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "cargo metadata failed")
    return json.loads(completed.stdout)


def source_violations(repo_root: Path) -> list[str]:
    violations = []
    for path in sorted((repo_root / "crates").rglob("*.rs")):
        matches = forbidden_source_matches(path.read_text(encoding="utf-8"))
        for pattern in matches:
            violations.append(f"{path.relative_to(repo_root)} matches /{pattern}/")
    return violations


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    try:
        metadata = load_metadata(repo_root)
    except (RuntimeError, json.JSONDecodeError) as error:
        print(f"offline runtime gate could not inspect dependency graph: {error}", file=sys.stderr)
        return 2

    violations = [
        *(f"forbidden resolved package: {name}" for name in forbidden_packages(metadata)),
        *source_violations(repo_root),
    ]
    if violations:
        print("offline runtime gate failed:", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1

    print("offline runtime gate passed: no HTTP/TLS client packages or socket transports")
    return 0


if __name__ == "__main__":
    sys.exit(main())
