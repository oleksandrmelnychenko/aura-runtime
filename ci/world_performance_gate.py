#!/usr/bin/env python3

import json
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


DEFAULT_INPUT = "crates/aura-core/data/world_lifecycle_suite/sofia_13_to_15_dense_2y.json"


@dataclass(frozen=True)
class PerfTier:
    name: str
    repeat_multiplier: int
    min_events: int
    max_seconds: float
    max_rss_mb: float


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return float(raw)


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def configured_tiers() -> dict[str, PerfTier]:
    return {
        "10k": PerfTier(
            name="10k",
            repeat_multiplier=env_int("AURA_PERF_10K_REPEAT_MULTIPLIER", 2),
            min_events=env_int("AURA_PERF_10K_MIN_EVENTS", 10_000),
            max_seconds=env_float("AURA_PERF_10K_MAX_SECONDS", 180.0),
            max_rss_mb=env_float("AURA_PERF_10K_MAX_RSS_MB", 768.0),
        ),
        "50k": PerfTier(
            name="50k",
            repeat_multiplier=env_int("AURA_PERF_50K_REPEAT_MULTIPLIER", 8),
            min_events=env_int("AURA_PERF_50K_MIN_EVENTS", 50_000),
            max_seconds=env_float("AURA_PERF_50K_MAX_SECONDS", 900.0),
            max_rss_mb=env_float("AURA_PERF_50K_MAX_RSS_MB", 1280.0),
        ),
        "100k": PerfTier(
            name="100k",
            repeat_multiplier=env_int("AURA_PERF_100K_REPEAT_MULTIPLIER", 15),
            min_events=env_int("AURA_PERF_100K_MIN_EVENTS", 100_000),
            max_seconds=env_float("AURA_PERF_100K_MAX_SECONDS", 1800.0),
            max_rss_mb=env_float("AURA_PERF_100K_MAX_RSS_MB", 2048.0),
        ),
    }


def selected_tiers() -> list[PerfTier]:
    tiers = configured_tiers()
    raw = os.environ.get("AURA_PERF_TIERS", "10k,50k,100k")
    names = [name.strip() for name in raw.split(",") if name.strip()]
    unknown = [name for name in names if name not in tiers]
    if unknown:
        raise SystemExit(f"unknown AURA_PERF_TIERS entries: {', '.join(unknown)}")
    return [tiers[name] for name in names]


def run_command(argv: list[str], cwd: Path, log_path: Path | None = None) -> int:
    print("+ " + " ".join(argv), flush=True)
    if log_path is None:
        return subprocess.run(argv, cwd=cwd, check=False).returncode

    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.run(
            argv,
            cwd=cwd,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    return process.returncode


def parse_time_report(path: Path, system: str | None = None) -> dict:
    text = path.read_text(encoding="utf-8")
    system = system or platform.system()
    if system == "Darwin":
        rss_bytes = int(match_required(text, r"(\d+)\s+maximum resident set size"))
        elapsed_raw = match_required(text, r"^real\s+([0-9.]+)$")
        user_seconds = float(match_required(text, r"^user\s+([0-9.]+)$"))
        system_seconds = float(match_required(text, r"^sys\s+([0-9.]+)$"))
        max_rss_mb = round(rss_bytes / (1024 * 1024), 3)
    else:
        rss_kb = int(
            match_required(text, r"Maximum resident set size \(kbytes\):\s+(\d+)")
        )
        elapsed_raw = match_required(
            text, r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s+(.+)"
        )
        user_seconds = float(
            match_required(text, r"User time \(seconds\):\s+([0-9.]+)")
        )
        system_seconds = float(
            match_required(text, r"System time \(seconds\):\s+([0-9.]+)")
        )
        max_rss_mb = round(rss_kb / 1024, 3)
    return {
        "elapsed_seconds": parse_elapsed_seconds(elapsed_raw.strip()),
        "user_seconds": user_seconds,
        "system_seconds": system_seconds,
        "max_rss_mb": max_rss_mb,
    }


def match_required(text: str, pattern: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise SystemExit(f"could not parse /usr/bin/time output pattern: {pattern}")
    return match.group(1)


def parse_elapsed_seconds(value: str) -> float:
    parts = value.split(":")
    if len(parts) == 2:
        minutes, seconds = parts
        return int(minutes) * 60 + float(seconds)
    if len(parts) == 3:
        hours, minutes, seconds = parts
        return int(hours) * 3600 + int(minutes) * 60 + float(seconds)
    return float(value)


def time_command(time_path: Path, binary: Path, arguments: list[str]) -> list[str]:
    if platform.system() == "Darwin":
        return [
            "/usr/bin/time",
            "-l",
            "-p",
            "-o",
            str(time_path),
            str(binary),
            *arguments,
        ]
    return [
        "/usr/bin/time",
        "-v",
        "-o",
        str(time_path),
        str(binary),
        *arguments,
    ]


def display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def check_report(tier: PerfTier, report: dict, timing: dict) -> list[str]:
    failures: list[str] = []
    context = report.get("context_store") or {}
    metrics = (report.get("metrics") or {}).get("overall") or {}

    if report.get("total_events", 0) < tier.min_events:
        failures.append(
            f"{tier.name}: total_events {report.get('total_events')} below {tier.min_events}"
        )
    if report.get("findings"):
        failures.append(f"{tier.name}: simulation report has findings")
    if "event_log" in report:
        failures.append(f"{tier.name}: report retained event_log despite --omit-event-log")
    if metrics.get("positive_recall") is not None and metrics["positive_recall"] < 0.95:
        failures.append(f"{tier.name}: positive_recall below 0.95")
    if (
        metrics.get("clean_false_positive_rate") is not None
        and metrics["clean_false_positive_rate"] > 0.01
    ):
        failures.append(f"{tier.name}: clean_false_positive_rate above 0.01")

    if timing["elapsed_seconds"] > tier.max_seconds:
        failures.append(
            f"{tier.name}: elapsed {timing['elapsed_seconds']:.3f}s above {tier.max_seconds:.3f}s"
        )
    if timing["max_rss_mb"] > tier.max_rss_mb:
        failures.append(
            f"{tier.name}: max RSS {timing['max_rss_mb']:.1f} MiB above {tier.max_rss_mb:.1f} MiB"
        )

    max_timelines = env_int("AURA_PERF_MAX_CONTEXT_TIMELINES", 200)
    max_timeline_events = env_int("AURA_PERF_MAX_TIMELINE_EVENTS", 500)
    max_total_timeline_events = env_int("AURA_PERF_MAX_TOTAL_TIMELINE_EVENTS", 100_000)
    max_contact_profiles = env_int("AURA_PERF_MAX_CONTACT_PROFILES", 1000)
    if context.get("timeline_count", 0) > max_timelines:
        failures.append(f"{tier.name}: context timeline_count exceeded {max_timelines}")
    if context.get("max_timeline_events", 0) > max_timeline_events:
        failures.append(f"{tier.name}: max_timeline_events exceeded {max_timeline_events}")
    if context.get("total_timeline_events", 0) > max_total_timeline_events:
        failures.append(f"{tier.name}: total_timeline_events exceeded {max_total_timeline_events}")
    if context.get("contact_profile_count", 0) > max_contact_profiles:
        failures.append(f"{tier.name}: contact_profile_count exceeded {max_contact_profiles}")

    return failures


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    artifact_dir = Path(os.environ.get("AURA_PERF_ARTIFACT_DIR", "artifacts/performance"))
    if not artifact_dir.is_absolute():
        artifact_dir = repo_root / artifact_dir
    artifact_dir.mkdir(parents=True, exist_ok=True)

    input_path = os.environ.get("AURA_PERF_INPUT", DEFAULT_INPUT)
    binary = repo_root / "target/release/examples/world_sim"

    if os.environ.get("AURA_PERF_SKIP_BUILD") != "1":
        build_rc = run_command(
            ["cargo", "build", "--release", "-p", "aura-core", "--example", "world_sim"],
            cwd=repo_root,
        )
        if build_rc != 0:
            return build_rc

    results = []
    failures = []
    for tier in selected_tiers():
        report_path = artifact_dir / f"world-performance-{tier.name}.json"
        time_path = artifact_dir / f"world-performance-{tier.name}.time.txt"
        log_path = artifact_dir / f"world-performance-{tier.name}.log"
        world_sim_arguments = [
            "--input",
            input_path,
            "--summary-only",
            "--output",
            str(report_path),
            "--redact-text",
            "--omit-event-log",
            "--require-clean",
            "--min-labeled-recall",
            "0.95",
            "--max-clean-fp-rate",
            "0.01",
            "--repeat-multiplier",
            str(tier.repeat_multiplier),
        ]
        argv = time_command(time_path, binary, world_sim_arguments)

        started = time.monotonic()
        rc = run_command(argv, cwd=repo_root, log_path=log_path)
        duration = round(time.monotonic() - started, 3)
        if rc != 0:
            failures.append(f"{tier.name}: command failed, see {log_path}")
            continue

        report = json.loads(report_path.read_text(encoding="utf-8"))
        timing = parse_time_report(time_path)
        tier_failures = check_report(tier, report, timing)
        failures.extend(tier_failures)
        result = {
            "tier": tier.name,
            "repeat_multiplier": tier.repeat_multiplier,
            "min_events": tier.min_events,
            "total_events": report.get("total_events"),
            "threat_events": report.get("threat_events"),
            "warn_events": report.get("warn_events"),
            "block_events": report.get("block_events"),
            "metrics": (report.get("metrics") or {}).get("overall"),
            "context_store": report.get("context_store"),
            "timing": timing,
            "wall_seconds_observed_by_harness": duration,
            "report_path": display_path(report_path, repo_root),
            "time_path": display_path(time_path, repo_root),
            "log_path": display_path(log_path, repo_root),
            "status": "fail" if tier_failures else "pass",
        }
        results.append(result)
        print(
            f"{tier.name}: events={result['total_events']} "
            f"elapsed={timing['elapsed_seconds']:.3f}s rss={timing['max_rss_mb']:.1f}MiB "
            f"context_events={(report.get('context_store') or {}).get('total_timeline_events')}",
            flush=True,
        )

    summary = {
        "schema_version": "aura_world_performance_gate.v1",
        "input": input_path,
        "status": "fail" if failures else "pass",
        "failures": failures,
        "tiers": results,
    }
    summary_path = artifact_dir / "world-performance-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(
        f"Wrote performance summary to {display_path(summary_path, repo_root)}",
        flush=True,
    )

    if failures:
        print("Performance gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
