#!/usr/bin/env python3

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path


SCHEMA_VERSION = "aura.evidence_manifest.v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a unified machine-readable manifest for AURA release evidence."
    )
    parser.add_argument("--output", required=True, help="Path to manifest JSON output.")
    parser.add_argument("--label", required=True, help="Short label for this evidence bundle.")
    parser.add_argument("--release-report", required=True, help="Path to release report JSON.")
    parser.add_argument(
        "--contract-evidence", required=True, help="Path to contract evidence JSON."
    )
    parser.add_argument("--ffi-soak", required=True, help="Path to FFI soak JSON evidence.")
    parser.add_argument(
        "--ffi-smoke",
        default=None,
        help="Optional path to FFI header smoke JSON evidence.",
    )
    parser.add_argument(
        "--dataset-evidence", required=True, help="Path to dataset evidence JSON."
    )
    parser.add_argument(
        "--audit-evidence", required=True, help="Path to audit evidence JSON."
    )
    return parser.parse_args()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_digest(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": path.as_posix(),
        "bytes": len(data),
        "sha256": sha256(data).hexdigest(),
    }


def load_json_artifact(path_str: str, required: bool) -> tuple[dict | None, dict]:
    path = Path(path_str)
    artifact = {
        "required": required,
        "exists": path.exists(),
        "path": path.as_posix(),
    }
    if not path.exists():
        artifact["status"] = "missing"
        return None, artifact

    artifact.update(file_digest(path))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        artifact["status"] = "invalid_json"
        artifact["error"] = str(error)
        return None, artifact

    artifact["status"] = "loaded"
    return payload, artifact


def release_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("overall_status")


def soak_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("status")


def smoke_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("status")


def dataset_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("status")


def audit_status(payload: dict | None) -> str | None:
    if payload is None:
        return None
    return payload.get("status")


def evidence_status(artifacts: dict, summary: dict) -> str:
    if any(meta["required"] and not meta["exists"] for meta in artifacts.values()):
        return "blocked"
    if any(meta["status"] == "invalid_json" for meta in artifacts.values()):
        return "blocked"
    if summary["release_report_status"] != "pass":
        return "fail"
    if summary["ffi_soak_status"] != "pass":
        return "fail"
    if summary["ffi_smoke_status"] not in (None, "pass"):
        return "fail"
    if summary["dataset_evidence_status"] != "pass":
        return "fail"
    if summary["audit_evidence_status"] != "pass":
        return "fail"
    if summary["audit_forbidden_fields_absent"] is not True:
        return "fail"
    return "pass"


def attach_payload_details(
    artifacts: dict,
    release_payload: dict | None,
    contract_payload: dict | None,
    soak_payload: dict | None,
    smoke_payload: dict | None,
    dataset_payload: dict | None,
    audit_payload: dict | None,
) -> None:
    if release_payload is not None:
        artifacts["release_report"]["observed_status"] = release_payload.get("overall_status")
        artifacts["release_report"]["schema_version"] = release_payload.get("schema_version")
    if contract_payload is not None:
        artifacts["contract_evidence"]["runtime_release_version"] = contract_payload.get(
            "runtime_release_version"
        )
        artifacts["contract_evidence"]["wire_package"] = contract_payload.get("wire", {}).get(
            "proto_package"
        )
    if soak_payload is not None:
        artifacts["ffi_soak"]["observed_status"] = soak_payload.get("status")
        artifacts["ffi_soak"]["failure_policy_version"] = soak_payload.get(
            "failure_policy_version"
        )
        artifacts["ffi_soak"]["failure_highlights"] = soak_payload.get(
            "failure_highlights", []
        )
    if smoke_payload is not None and "ffi_smoke" in artifacts:
        artifacts["ffi_smoke"]["observed_status"] = smoke_payload.get("status")
        artifacts["ffi_smoke"]["compiler"] = smoke_payload.get("compiler")
    if dataset_payload is not None:
        artifacts["dataset_evidence"]["observed_status"] = dataset_payload.get("status")
        artifacts["dataset_evidence"]["dataset_count"] = len(dataset_payload.get("datasets", []))
    if audit_payload is not None:
        artifacts["audit_evidence"]["observed_status"] = audit_payload.get("status")
        artifacts["audit_evidence"]["audit_schema_version"] = audit_payload.get(
            "audit_schema_version"
        )
        artifacts["audit_evidence"]["forbidden_fields_absent"] = audit_payload.get(
            "forbidden_fields_absent"
        )


def main() -> int:
    args = parse_args()

    release_payload, release_artifact = load_json_artifact(args.release_report, required=True)
    contract_payload, contract_artifact = load_json_artifact(args.contract_evidence, required=True)
    soak_payload, soak_artifact = load_json_artifact(args.ffi_soak, required=True)
    dataset_payload, dataset_artifact = load_json_artifact(args.dataset_evidence, required=True)
    audit_payload, audit_artifact = load_json_artifact(args.audit_evidence, required=True)
    smoke_payload, smoke_artifact = load_json_artifact(
        args.ffi_smoke, required=args.ffi_smoke is not None
    ) if args.ffi_smoke else (None, None)

    artifacts = {
        "release_report": release_artifact,
        "contract_evidence": contract_artifact,
        "ffi_soak": soak_artifact,
        "dataset_evidence": dataset_artifact,
        "audit_evidence": audit_artifact,
    }
    if smoke_artifact is not None:
        artifacts["ffi_smoke"] = smoke_artifact

    attach_payload_details(
        artifacts,
        release_payload=release_payload,
        contract_payload=contract_payload,
        soak_payload=soak_payload,
        smoke_payload=smoke_payload,
        dataset_payload=dataset_payload,
        audit_payload=audit_payload,
    )

    request_limits = (
        contract_payload.get("abi", {}).get("request_limits_bytes", [])
        if contract_payload is not None
        else []
    )
    summary = {
        "runtime_release_version": (
            contract_payload.get("runtime_release_version") if contract_payload else None
        ),
        "wire_package": (
            contract_payload.get("wire", {}).get("proto_package") if contract_payload else None
        ),
        "wire_major_version": (
            contract_payload.get("wire", {}).get("wire_major_version") if contract_payload else None
        ),
        "state_schema_version": (
            contract_payload.get("persisted_state", {}).get("schema_version")
            if contract_payload
            else None
        ),
        "release_report_status": release_status(release_payload),
        "release_report_schema_version": (
            release_payload.get("schema_version") if release_payload else None
        ),
        "ffi_request_limit_count": len(request_limits),
        "ffi_import_context_max_bytes": next(
            (
                item.get("max_bytes")
                for item in request_limits
                if item.get("constant_name") == "MAX_IMPORT_CONTEXT_REQUEST_BYTES"
            ),
            None,
        ),
        "ffi_soak_status": soak_status(soak_payload),
        "ffi_soak_iterations": soak_payload.get("iterations") if soak_payload else None,
        "ffi_soak_attempts_run": soak_payload.get("attempts_run") if soak_payload else None,
        "ffi_soak_failure_category": (
            soak_payload.get("failure_category") if soak_payload else None
        ),
        "ffi_soak_failure_summary": (
            soak_payload.get("failure_summary") if soak_payload else None
        ),
        "ffi_smoke_status": smoke_status(smoke_payload),
        "dataset_evidence_status": dataset_status(dataset_payload),
        "dataset_count": len(dataset_payload.get("datasets", [])) if dataset_payload else None,
        "audit_evidence_status": audit_status(audit_payload),
        "audit_schema_version": (
            audit_payload.get("audit_schema_version") if audit_payload else None
        ),
        "audit_forbidden_fields_absent": (
            audit_payload.get("forbidden_fields_absent") if audit_payload else None
        ),
        "ffi_export_count": (
            len(contract_payload.get("abi", {}).get("exported_functions", []))
            if contract_payload
            else None
        ),
    }

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": now_utc(),
        "label": args.label,
        "evidence_status": None,
        "summary": summary,
        "artifacts": artifacts,
    }
    manifest["evidence_status"] = evidence_status(artifacts, summary)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0 if manifest["evidence_status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
