#!/usr/bin/env python3

"""Capture and compare deterministic AURA Core refactor evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any


SNAPSHOT_SCHEMA_VERSION = "aura.refactor_baseline.v1"
DIFF_SCHEMA_VERSION = "aura.refactor_diff.v1"
APPROVAL_SCHEMA_VERSION = "aura.refactor_diff_approvals.v1"
ALLOWED_CLASSIFICATIONS = {
    "structural_only",
    "approved_safety_improvement",
}
PERFORMANCE_ELAPSED_HEADROOM = 1.20
PERFORMANCE_RSS_HEADROOM = 1.15
PERFORMANCE_MIN_ELAPSED_LIMIT_SECONDS = {
    "10k": 30.0,
    "50k": 300.0,
    "100k": 900.0,
}
PERFORMANCE_MIN_RSS_LIMIT_MB = {
    "10k": 512.0,
    "50k": 1024.0,
    "100k": 1536.0,
}
MISSING = {"$aura_missing": True}


class RefactorBaselineError(RuntimeError):
    """Raised when refactor evidence cannot be captured or validated."""


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture or compare deterministic AURA Core refactor evidence."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser(
        "snapshot",
        help="Capture a normalized refactor evidence snapshot.",
    )
    snapshot.add_argument("--output", required=True)
    snapshot.add_argument("--baseline-id", required=True)
    snapshot.add_argument("--contract-evidence", required=True)
    snapshot.add_argument("--release-report", required=True)
    snapshot.add_argument("--pilot-regression-report", required=True)
    snapshot.add_argument("--world-lifecycle-report", required=True)
    snapshot.add_argument("--world-performance-report")
    snapshot.add_argument(
        "--apple-release-manifest",
        default="dist/apple/release-manifest.json",
    )
    snapshot.add_argument("--source-revision")
    snapshot.add_argument(
        "--source-tree-state",
        choices=("auto", "clean", "dirty"),
        default="auto",
    )

    compare = subparsers.add_parser(
        "compare",
        help="Compare a candidate snapshot with the checked-in baseline.",
    )
    compare.add_argument("--baseline", required=True)
    compare.add_argument("--candidate", required=True)
    compare.add_argument("--output", required=True)
    compare.add_argument("--approvals")
    compare.add_argument("--require-pass", action="store_true")

    return parser.parse_args()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RefactorBaselineError(f"required JSON artifact is missing: {path}") from error
    except json.JSONDecodeError as error:
        raise RefactorBaselineError(f"invalid JSON artifact {path}: {error}") from error


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_checked(argv: list[str], cwd: Path) -> str:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RefactorBaselineError(
            f"command failed ({' '.join(argv)}): {detail or 'no output'}"
        )
    return completed.stdout


def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


def file_evidence(path: Path, workspace_root: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(workspace_root).as_posix(),
        "bytes": len(data),
        "sha256": sha256_hex(data),
    }


def workspace_path(path: str, workspace_root: Path) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else workspace_root / candidate


def source_snapshot(
    workspace_root: Path,
    requested_revision: str | None,
    requested_tree_state: str,
) -> dict[str, Any]:
    revision = requested_revision or run_checked(
        ["git", "rev-parse", "HEAD"], workspace_root
    ).strip()
    dirty = (
        bool(
            run_checked(
                ["git", "status", "--porcelain", "--untracked-files=normal"],
                workspace_root,
            ).strip()
        )
        if requested_tree_state == "auto"
        else requested_tree_state == "dirty"
    )
    return {
        "revision": revision,
        "tree_dirty": dirty,
    }


def workspace_snapshot(workspace_root: Path) -> dict[str, Any]:
    raw = run_checked(
        [
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ],
        workspace_root,
    )
    metadata = json.loads(raw)
    workspace_member_ids = set(metadata["workspace_members"])
    workspace_packages = [
        package
        for package in metadata["packages"]
        if package["id"] in workspace_member_ids
    ]
    workspace_names = {package["name"] for package in workspace_packages}

    packages = []
    for package in workspace_packages:
        internal_dependencies = sorted(
            {
                dependency["name"]
                for dependency in package.get("dependencies", [])
                if dependency["name"] in workspace_names
            }
        )
        manifest_path = Path(package["manifest_path"])
        packages.append(
            {
                "name": package["name"],
                "version": package["version"],
                "manifest_path": manifest_path.relative_to(workspace_root).as_posix(),
                "internal_dependencies": internal_dependencies,
            }
        )

    packages.sort(key=lambda package: package["name"])
    return {
        "package_count": len(packages),
        "packages": packages,
    }


def fixture_inventory(workspace_root: Path) -> list[dict[str, Any]]:
    roots = [
        workspace_root / "crates/aura-core/data",
        workspace_root / "crates/aura-kids/data",
        workspace_root / "crates/aura-military/data",
        workspace_root / "crates/aura-patterns/data",
    ]
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        files.extend(
            path
            for path in root.rglob("*.json")
            if path.name != "refactor_baseline_v1.json"
        )
    return [file_evidence(path, workspace_root) for path in sorted(files)]


def protobuf_fixture_inventory(workspace_root: Path) -> list[dict[str, Any]]:
    fixture_root = workspace_root / "crates/aura-proto/tests/fixtures"
    return [
        file_evidence(path, workspace_root)
        for path in sorted(fixture_root.glob("*.pb"))
    ]


def contract_snapshot(
    workspace_root: Path,
    contract_path: Path,
    apple_manifest_path: Path,
) -> dict[str, Any]:
    contract = load_json(contract_path)
    if not isinstance(contract, dict):
        raise RefactorBaselineError("contract evidence must be a JSON object")
    contract = {
        key: value
        for key, value in contract.items()
        if key != "generated_at_utc"
    }

    apple_manifest = load_json(apple_manifest_path)
    if not isinstance(apple_manifest, dict):
        raise RefactorBaselineError("Apple release manifest must be a JSON object")

    return {
        "contract_evidence": contract,
        "protobuf_compatibility_fixtures": protobuf_fixture_inventory(workspace_root),
        "apple_artifact": {
            "manifest_file": file_evidence(apple_manifest_path, workspace_root),
            "release_manifest": apple_manifest,
        },
    }


def without_keys(value: Any, excluded: set[str]) -> Any:
    if isinstance(value, dict):
        return {
            key: without_keys(child, excluded)
            for key, child in value.items()
            if key not in excluded
        }
    if isinstance(value, list):
        return [without_keys(child, excluded) for child in value]
    return value


def scalar_fields(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {
        key: child
        for key, child in value.items()
        if not isinstance(child, (dict, list))
    }


def metric_projection(value: Any, include_by_threat: bool = True) -> Any:
    if not isinstance(value, dict):
        return value
    projected = scalar_fields(value) or {}
    if include_by_threat and isinstance(value.get("by_threat"), list):
        projected["by_threat"] = [
            scalar_fields(item) if isinstance(item, dict) else item
            for item in value["by_threat"]
        ]
    return projected


def policy_projection(value: Any, include_scenarios: bool = True) -> Any:
    if not isinstance(value, dict):
        return value
    projected = scalar_fields(value) or {}
    if include_scenarios and isinstance(value.get("scenarios"), list):
        projected["scenarios"] = value["scenarios"]
    return projected


def support_projection(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    return {
        "calibration_examples": value.get("calibration_examples"),
        "positive_scenarios": value.get("positive_scenarios"),
        "negative_scenarios": value.get("negative_scenarios"),
        "onset_cases": value.get("onset_cases"),
        "reportable": value.get("reportable"),
        "release_blocking_ready": value.get("release_blocking_ready"),
        "missing_release_blocking": value.get("missing_release_blocking"),
    }


def release_projection(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise RefactorBaselineError("release report must be a JSON object")

    suites = []
    for suite in report.get("suites", []):
        slices = []
        for slice_report in suite.get("slices", []):
            slices.append(
                {
                    "group": slice_report.get("group"),
                    "slice_id": slice_report.get("slice_id"),
                    "support_enforcement": slice_report.get("support_enforcement"),
                    "status": slice_report.get("status"),
                    "support": support_projection(slice_report.get("support")),
                    "evaluation": metric_projection(
                        slice_report.get("evaluation"),
                        include_by_threat=False,
                    ),
                    "policy": policy_projection(
                        slice_report.get("policy"),
                        include_scenarios=False,
                    ),
                }
            )
        suites.append(
            {
                "suite_id": suite.get("suite_id"),
                "status": suite.get("status"),
                "missing_required_slices": suite.get("missing_required_slices"),
                "evaluation": metric_projection(suite.get("evaluation")),
                "evaluation_gates": suite.get("evaluation_gates"),
                "policy": policy_projection(suite.get("policy")),
                "slices": slices,
                "social_context_inference": suite.get("social_context_inference"),
            }
        )

    return {
        "schema_version": report.get("schema_version"),
        "runtime_version": report.get("runtime_version"),
        "overall_status": report.get("overall_status"),
        "support_thresholds": report.get("support_thresholds"),
        "drift_thresholds": report.get("drift_thresholds"),
        "suites": suites,
        "drift_checks": report.get("drift_checks"),
        "wave1_model_profile_drift": report.get("wave1_model_profile_drift"),
        "wave1_on_device_checks": report.get("wave1_on_device_checks"),
        "wave1_rollback_decision": report.get("wave1_rollback_decision"),
    }


def calibration_projection(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    projected = scalar_fields(value) or {}
    if isinstance(value.get("by_threat"), list):
        projected["by_threat"] = [
            scalar_fields(item) if isinstance(item, dict) else item
            for item in value["by_threat"]
        ]
    return projected


def classification_projection(value: Any, include_scenarios: bool) -> Any:
    if not isinstance(value, dict):
        return value
    projected = scalar_fields(value) or {}
    if include_scenarios and isinstance(value.get("scenarios"), list):
        projected["scenarios"] = value["scenarios"]
    return projected


def pilot_evaluation_projection(value: Any, include_scenarios: bool) -> Any:
    if not isinstance(value, dict):
        return value
    language_slices = []
    for language_slice in value.get("language_slices", []):
        language_slices.append(
            {
                "language": language_slice.get("language"),
                "scenario_count": language_slice.get("scenario_count"),
                "calibration": calibration_projection(
                    language_slice.get("calibration")
                ),
                "lead_time": language_slice.get("lead_time"),
                "classification": classification_projection(
                    language_slice.get("classification"),
                    include_scenarios=False,
                ),
            }
        )
    return {
        "calibration": calibration_projection(value.get("calibration")),
        "lead_time": value.get("lead_time"),
        "classification": classification_projection(
            value.get("classification"),
            include_scenarios=include_scenarios,
        ),
        "language_slices": language_slices,
    }


def pilot_dimension_entry_projection(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    projected = scalar_fields(value) or {}
    if "scenario_names" in value:
        projected["scenario_names"] = value["scenario_names"]
    if "evaluation" in value:
        projected["evaluation"] = pilot_evaluation_projection(
            value["evaluation"],
            include_scenarios=False,
        )
    if "policy" in value:
        projected["policy"] = policy_projection(
            value["policy"],
            include_scenarios=False,
        )
    return projected


def pilot_dimension_projection(value: Any) -> Any:
    if isinstance(value, list):
        return [pilot_dimension_entry_projection(item) for item in value]
    if isinstance(value, dict):
        return {
            key: pilot_dimension_entry_projection(item)
            for key, item in value.items()
        }
    return value


def pilot_projection(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise RefactorBaselineError("pilot regression report must be a JSON object")

    return {
        "schema_version": report.get("schema_version"),
        "overall_status": report.get("overall_status"),
        "manifest": report.get("manifest"),
        "evaluation": pilot_evaluation_projection(
            report.get("evaluation"),
            include_scenarios=True,
        ),
        "evaluation_gates": report.get("evaluation_gates"),
        "policy": policy_projection(report.get("policy")),
        "policy_gates": report.get("policy_gates"),
        "language_gates": report.get("language_gates"),
        "source_family_gates": report.get("source_family_gates"),
        "by_case_class": pilot_dimension_projection(report.get("by_case_class")),
        "by_language": pilot_dimension_projection(report.get("by_language")),
        "by_pilot_slice": pilot_dimension_projection(report.get("by_pilot_slice")),
        "by_source_family": pilot_dimension_projection(
            report.get("by_source_family")
        ),
    }


def world_metrics_projection(value: Any, include_context_slices: bool) -> Any:
    if not isinstance(value, dict):
        return value
    projected = {
        "overall": value.get("overall"),
        "by_expected_threat": value.get("by_expected_threat"),
    }
    if include_context_slices:
        projected.update(
            {
                "by_language": value.get("by_language"),
                "by_relationship": value.get("by_relationship"),
                "by_surface": value.get("by_surface"),
            }
        )
    return projected


def world_report_projection(
    report: Any,
    include_context_slices: bool = False,
) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise RefactorBaselineError("world lifecycle report entry must be a JSON object")
    return {
        "schema_version": report.get("schema_version"),
        "label": report.get("label"),
        "total_events": report.get("total_events"),
        "threat_events": report.get("threat_events"),
        "warn_events": report.get("warn_events"),
        "block_events": report.get("block_events"),
        "action_counts": report.get("action_counts"),
        "threat_counts": report.get("threat_counts"),
        "alert_counts": report.get("alert_counts"),
        "metrics": world_metrics_projection(
            report.get("metrics"),
            include_context_slices=include_context_slices,
        ),
        "context_store": report.get("context_store"),
        "findings": report.get("findings"),
    }


def world_lifecycle_projection(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise RefactorBaselineError("world lifecycle report must be a JSON object")
    projected = world_report_projection(report, include_context_slices=True)
    if report.get("schema_version") == "world_suite.v1":
        projected["total_worlds"] = report.get("total_worlds")
        projected["total_findings"] = report.get("total_findings")
        projected["reports"] = [
            world_report_projection(world)
            for world in report.get("reports", [])
        ]
    return projected


def performance_projection(report: Any | None) -> dict[str, Any] | None:
    if report is None:
        return None
    if not isinstance(report, dict):
        raise RefactorBaselineError("world performance report must be a JSON object")

    tiers = []
    for tier in report.get("tiers", []):
        tiers.append(
            {
                "tier": tier.get("tier"),
                "repeat_multiplier": tier.get("repeat_multiplier"),
                "min_events": tier.get("min_events"),
                "total_events": tier.get("total_events"),
                "threat_events": tier.get("threat_events"),
                "warn_events": tier.get("warn_events"),
                "block_events": tier.get("block_events"),
                "metrics": tier.get("metrics"),
                "context_store": tier.get("context_store"),
                "timing": tier.get("timing"),
                "status": tier.get("status"),
            }
        )
    tiers.sort(key=lambda tier: str(tier["tier"]))
    return {
        "schema_version": report.get("schema_version"),
        "input": report.get("input"),
        "status": report.get("status"),
        "failures": report.get("failures"),
        "tiers": tiers,
    }


def build_snapshot(args: argparse.Namespace, workspace_root: Path) -> dict[str, Any]:
    performance_report = (
        load_json(workspace_path(args.world_performance_report, workspace_root))
        if args.world_performance_report
        else None
    )
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "captured_at_utc": now_utc(),
        "baseline_id": args.baseline_id,
        "source": source_snapshot(
            workspace_root,
            args.source_revision,
            args.source_tree_state,
        ),
        "workspace": workspace_snapshot(workspace_root),
        "contracts": contract_snapshot(
            workspace_root,
            workspace_path(args.contract_evidence, workspace_root),
            workspace_path(args.apple_release_manifest, workspace_root),
        ),
        "fixture_inputs": fixture_inventory(workspace_root),
        "behavior": {
            "release": release_projection(
                load_json(workspace_path(args.release_report, workspace_root))
            ),
            "pilot_regression": pilot_projection(
                load_json(
                    workspace_path(args.pilot_regression_report, workspace_root)
                )
            ),
            "world_lifecycle": world_lifecycle_projection(
                load_json(
                    workspace_path(args.world_lifecycle_report, workspace_root)
                )
            ),
        },
        "performance": performance_projection(performance_report),
    }


def json_pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def collect_changes(
    baseline: Any,
    candidate: Any,
    path: str = "",
) -> list[dict[str, Any]]:
    if isinstance(baseline, dict) and isinstance(candidate, dict):
        changes = []
        for key in sorted(set(baseline) | set(candidate)):
            child_path = f"{path}/{json_pointer_part(str(key))}"
            if key not in baseline:
                changes.append(
                    {
                        "path": child_path,
                        "baseline": MISSING,
                        "candidate": candidate[key],
                    }
                )
            elif key not in candidate:
                changes.append(
                    {
                        "path": child_path,
                        "baseline": baseline[key],
                        "candidate": MISSING,
                    }
                )
            else:
                changes.extend(
                    collect_changes(baseline[key], candidate[key], child_path)
                )
        return changes

    if isinstance(baseline, list) and isinstance(candidate, list):
        changes = []
        for index in range(max(len(baseline), len(candidate))):
            child_path = f"{path}/{index}"
            if index >= len(baseline):
                changes.append(
                    {
                        "path": child_path,
                        "baseline": MISSING,
                        "candidate": candidate[index],
                    }
                )
            elif index >= len(candidate):
                changes.append(
                    {
                        "path": child_path,
                        "baseline": baseline[index],
                        "candidate": MISSING,
                    }
                )
            else:
                changes.extend(
                    collect_changes(baseline[index], candidate[index], child_path)
                )
        return changes

    if baseline != candidate:
        return [{"path": path or "/", "baseline": baseline, "candidate": candidate}]
    return []


def file_evidence_by_path(value: Any) -> Any:
    """Normalize file inventories so additions do not shift every list index."""
    if not isinstance(value, list):
        return value

    indexed: dict[str, Any] = {}
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            return value
        path = item["path"]
        if path in indexed:
            return value
        indexed[path] = {
            key: child for key, child in item.items() if key != "path"
        }
    return indexed


def comparison_surface(snapshot: dict[str, Any]) -> dict[str, Any]:
    performance = snapshot.get("performance")
    if isinstance(performance, dict):
        performance = {
            **performance,
            "tiers": [
                {
                    key: value
                    for key, value in tier.items()
                    if key != "timing"
                }
                for tier in performance.get("tiers", [])
            ],
        }
    return {
        "workspace": snapshot.get("workspace"),
        "contracts": snapshot.get("contracts"),
        "fixture_inputs": file_evidence_by_path(snapshot.get("fixture_inputs")),
        "behavior": snapshot.get("behavior"),
        "performance": performance,
    }


def performance_envelope_changes(
    baseline_snapshot: dict[str, Any],
    candidate_snapshot: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    baseline = baseline_snapshot.get("performance")
    candidate = candidate_snapshot.get("performance")
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        return [], []

    baseline_tiers = {
        tier.get("tier"): tier
        for tier in baseline.get("tiers", [])
        if tier.get("tier") is not None
    }
    candidate_tiers = {
        tier.get("tier"): tier
        for tier in candidate.get("tiers", [])
        if tier.get("tier") is not None
    }
    changes = []
    observations = []
    for tier_name in sorted(set(baseline_tiers) & set(candidate_tiers)):
        baseline_timing = baseline_tiers[tier_name].get("timing") or {}
        candidate_timing = candidate_tiers[tier_name].get("timing") or {}
        elapsed_limit = baseline_timing.get("elapsed_seconds")
        rss_limit = baseline_timing.get("max_rss_mb")
        if isinstance(elapsed_limit, (int, float)):
            elapsed_limit = max(
                elapsed_limit * PERFORMANCE_ELAPSED_HEADROOM,
                PERFORMANCE_MIN_ELAPSED_LIMIT_SECONDS.get(tier_name, 0.0),
            )
        if isinstance(rss_limit, (int, float)):
            rss_limit = max(
                rss_limit * PERFORMANCE_RSS_HEADROOM,
                PERFORMANCE_MIN_RSS_LIMIT_MB.get(tier_name, 0.0),
            )

        measured_elapsed = candidate_timing.get("elapsed_seconds")
        measured_rss = candidate_timing.get("max_rss_mb")
        elapsed_pass = (
            isinstance(elapsed_limit, (int, float))
            and isinstance(measured_elapsed, (int, float))
            and measured_elapsed <= elapsed_limit
        )
        rss_pass = (
            isinstance(rss_limit, (int, float))
            and isinstance(measured_rss, (int, float))
            and measured_rss <= rss_limit
        )
        observations.append(
            {
                "tier": tier_name,
                "elapsed_seconds": measured_elapsed,
                "elapsed_limit_seconds": elapsed_limit,
                "max_rss_mb": measured_rss,
                "max_rss_limit_mb": rss_limit,
                "status": "pass" if elapsed_pass and rss_pass else "regression",
            }
        )
        if not elapsed_pass:
            changes.append(
                {
                    "path": f"/performance/tiers/{tier_name}/timing/elapsed_seconds",
                    "baseline": elapsed_limit,
                    "candidate": measured_elapsed,
                }
            )
        if not rss_pass:
            changes.append(
                {
                    "path": f"/performance/tiers/{tier_name}/timing/max_rss_mb",
                    "baseline": rss_limit,
                    "candidate": measured_rss,
                }
            )
    return changes, observations


def load_approvals(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RefactorBaselineError("approval document must be a JSON object")
    if payload.get("schema_version") != APPROVAL_SCHEMA_VERSION:
        raise RefactorBaselineError(
            f"approval schema must be {APPROVAL_SCHEMA_VERSION}"
        )
    approvals = payload.get("approvals")
    if not isinstance(approvals, list):
        raise RefactorBaselineError("approval document must contain an approvals array")
    return approvals


def classify_changes(
    changes: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    approvals_by_path: dict[str, dict[str, Any]] = {}
    invalid_approvals = []
    for approval in approvals:
        if not isinstance(approval, dict):
            invalid_approvals.append(
                {"approval": approval, "error": "approval must be an object"}
            )
            continue
        path = approval.get("path")
        classification = approval.get("classification")
        reason = approval.get("reason")
        if not isinstance(path, str) or not path.startswith("/"):
            invalid_approvals.append(
                {"approval": approval, "error": "approval path must be a JSON pointer"}
            )
            continue
        if path in approvals_by_path:
            invalid_approvals.append(
                {"approval": approval, "error": f"duplicate approval path: {path}"}
            )
            continue
        if classification not in ALLOWED_CLASSIFICATIONS:
            invalid_approvals.append(
                {
                    "approval": approval,
                    "error": f"unsupported classification: {classification}",
                }
            )
            continue
        if not isinstance(reason, str) or not reason.strip():
            invalid_approvals.append(
                {"approval": approval, "error": "approval reason must not be empty"}
            )
            continue
        approvals_by_path[path] = approval

    classified = []
    used_paths = set()
    for change in changes:
        approval = approvals_by_path.get(change["path"])
        if approval is None:
            classified.append({**change, "classification": "regression"})
            continue
        if (
            approval.get("baseline") != change["baseline"]
            or approval.get("candidate") != change["candidate"]
        ):
            invalid_approvals.append(
                {
                    "approval": approval,
                    "error": "approved values do not exactly match the observed diff",
                }
            )
            classified.append({**change, "classification": "regression"})
            continue
        used_paths.add(change["path"])
        classified.append(
            {
                **change,
                "classification": approval["classification"],
                "reason": approval["reason"],
            }
        )

    for path, approval in approvals_by_path.items():
        if path not in used_paths:
            invalid_approvals.append(
                {
                    "approval": approval,
                    "error": "stale approval does not match a current diff",
                }
            )
    return classified, invalid_approvals


def validate_snapshot(snapshot: Any, label: str) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise RefactorBaselineError(f"{label} snapshot must be a JSON object")
    if snapshot.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        raise RefactorBaselineError(
            f"{label} snapshot schema must be {SNAPSHOT_SCHEMA_VERSION}"
        )
    return snapshot


def build_diff(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    approvals: list[dict[str, Any]],
) -> dict[str, Any]:
    changes = collect_changes(
        comparison_surface(baseline),
        comparison_surface(candidate),
    )
    performance_changes, performance_observations = performance_envelope_changes(
        baseline,
        candidate,
    )
    changes.extend(performance_changes)
    changes.sort(key=lambda change: change["path"])
    classified, invalid_approvals = classify_changes(changes, approvals)

    counts = {
        "structural_only": 0,
        "approved_safety_improvement": 0,
        "regression": 0,
    }
    for change in classified:
        counts[change["classification"]] += 1
    status = (
        "pass"
        if counts["regression"] == 0 and not invalid_approvals
        else "fail"
    )
    return {
        "schema_version": DIFF_SCHEMA_VERSION,
        "generated_at_utc": now_utc(),
        "status": status,
        "baseline": {
            "baseline_id": baseline.get("baseline_id"),
            "source": baseline.get("source"),
        },
        "candidate": {
            "baseline_id": candidate.get("baseline_id"),
            "source": candidate.get("source"),
        },
        "summary": {
            "change_count": len(classified),
            **counts,
            "invalid_approval_count": len(invalid_approvals),
        },
        "performance_observations": performance_observations,
        "changes": classified,
        "invalid_approvals": invalid_approvals,
    }


def main() -> int:
    args = parse_args()
    workspace_root = Path(__file__).resolve().parents[1]
    try:
        if args.command == "snapshot":
            snapshot = build_snapshot(args, workspace_root)
            write_json(Path(args.output), snapshot)
            print(
                "refactor evidence snapshot written to "
                f"{args.output} (baseline_id={args.baseline_id})",
                file=sys.stderr,
            )
            return 0

        baseline = validate_snapshot(load_json(Path(args.baseline)), "baseline")
        candidate = validate_snapshot(load_json(Path(args.candidate)), "candidate")
        approvals = load_approvals(Path(args.approvals) if args.approvals else None)
        report = build_diff(baseline, candidate, approvals)
        write_json(Path(args.output), report)
        print(
            "refactor diff written to "
            f"{args.output} (status={report['status']}, "
            f"changes={report['summary']['change_count']})",
            file=sys.stderr,
        )
        return 1 if args.require_pass and report["status"] != "pass" else 0
    except RefactorBaselineError as error:
        print(f"refactor baseline error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
