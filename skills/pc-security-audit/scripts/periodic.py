#!/usr/bin/env python3
"""Explicit local snapshots and comparisons; no collection, scheduler or remediation.

Inputs and checksums are local observations, never proof of consent or host trust.
Python 3.11+, standard library only. Raw collector output is not persisted here.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

# -I -S excludes site customizations and the working/script directories from
# module search. Load only this package's explicitly trusted sibling helper.
_spec = importlib.util.spec_from_file_location("pc_security_audit_helper", Path(__file__).resolve().with_name("audit.py"))
_helper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helper)
display, exact_parent, private_path, read_plan, verify_regular_descriptor = (
    getattr(_helper, name) for name in ("display", "exact_parent", "private_path", "read_plan", "verify_regular_descriptor"))

VERSION = 1
STATUSES = {"PASS", "FAIL", "PARTIAL", "NOT RUN", "NOT ASSESSED"}
SNAPSHOT_KEYS = {"schema_version", "kind", "machine_id", "platform", "architecture",
                 "environment", "scope_id", "collector_version", "observed_at",
                 "trust_assessment", "checks", "sha256"}
MAX_CHECKS = 2048
SAFE_ERRORS = {
    "Collector is stale or from the future": "collector_stale_or_future",
    "Nonchronological or stale observations": "snapshot_stale_or_nonchronological",
    "Incompatible machine, environment, scope or collector": "incompatible_identity_scope_or_version",
    "Invalid snapshot checksum or trust claim": "snapshot_integrity_or_trust_claim_invalid",
    "Snapshot exceeds local storage limit": "snapshot_size_limit",
    "Only bounded regular JSON files are accepted": "input_size_limit",
    "Input grew beyond the limit": "input_grew_beyond_limit",
    "Duplicate JSON key": "duplicate_json_key",
    "Non-finite JSON value": "nonfinite_json_value",
    "Reparse/symlink path rejected": "symlink_or_reparse_path",
    "Ambiguous Windows JSON path rejected before opening": "ambiguous_windows_path",
}


def error_code(exc: Exception) -> str:
    """Only fixed codes: never echo input, paths, native errors or JSON fragments."""
    if isinstance(exc, FileExistsError):
        return "output_exists_no_overwrite"
    if isinstance(exc, PermissionError):
        return "access_denied"
    if isinstance(exc, json.JSONDecodeError):
        return "invalid_json"
    if type(exc) is ValueError:
        return SAFE_ERRORS.get(str(exc), "invalid_input_schema_or_state")
    return "inaccessible_path_or_invalid_input"


def timestamp(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError("Timestamp must be text")
    result = dt.datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("Timestamp needs a timezone")
    return result


def identifier(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value) is not None


def version_label(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", value) is not None


def digest(value: dict[str, Any]) -> str:
    body = {key: item for key, item in value.items() if key != "sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False,
                                     allow_nan=False, separators=(",", ":")).encode()).hexdigest()


def _scalar(value: Any) -> bool:
    return value is None or type(value) in (bool, int) or isinstance(value, str) and len(value) <= 256


def _facts(check: dict[str, Any]) -> dict[str, Any]:
    """Whitelist stable fields; never retain arbitrary output, args, env or secrets."""
    facts: dict[str, Any] = {}
    name = check["check"]
    if name in {"local_skill_triage", "local_cisco_report", "local_package_advisories"}:
        data = check.get("data")
        required = {"local_skill_triage": {"files_read", "bytes_read", "coverage_gaps", "finding_count"},
                    "local_cisco_report": {"scanned_skills", "coverage_gaps", "suppressed_findings", "critical", "high", "medium", "low", "info"},
                    "local_package_advisories": {"packages_assessed", "advisory_records", "coverage_gaps", "finding_count", "cache_age_minutes"}}[name]
        missing = 0
        for key in required:
            value = data.get(key) if isinstance(data, dict) else None
            if type(value) is int and 0 <= value <= 10_000_000:
                facts[key] = value
            else:
                missing += 1
        fingerprint = data.get("evidence_fingerprint") if isinstance(data, dict) else None
        if isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            facts["evidence_fingerprint"] = fingerprint
        else:
            missing += 1
        facts["metadata_fields_missing"] = missing
    if name in {"firewall_stealth", "screen_lock_password", "screen_lock_grace"}:
        facts["protection_fields_missing"] = 0
        if type(check.get("meets_baseline")) is bool:
            facts["meets_baseline"] = check["meets_baseline"]
        else:
            facts["protection_fields_missing"] = 1
        if name == "screen_lock_grace":
            if type(check.get("seconds")) is int and 0 <= check["seconds"] <= 86400:
                facts["seconds"] = check["seconds"]
            else:
                facts["protection_fields_missing"] += 1
    if name in {"sip", "gatekeeper", "filevault", "firewall"} and "data" not in check:
        facts["protection_fields_missing"] = 0
        if type(check.get("enabled")) is bool:
            facts["enabled"] = check["enabled"]
        else:
            facts["protection_fields_missing"] = 1
    if name == "os_version" and isinstance(check.get("output"), str):
        value = check["output"].strip()
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", value):
            facts["version"] = value
    if name == "os_build" and isinstance(check.get("output"), str):
        value = check["output"].strip()
        if re.fullmatch(r"[A-Za-z0-9._-]{1,80}", value):
            facts["build"] = value
    entries = check.get("entries")
    if isinstance(entries, list):
        fingerprints, missing_metadata = {}, 0
        for row in entries:
            if not isinstance(row, dict):
                raise ValueError("Invalid metadata entry")
            path, fingerprint = row.get("path"), row.get("metadata_fingerprint")
            if isinstance(path, str) and isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                if private_path(path):
                    raise ValueError("Sensitive entry in collector data")
                fingerprints[hashlib.sha256(path.encode()).hexdigest()] = fingerprint
            else:
                missing_metadata += 1
        facts["entry_fingerprints"] = fingerprints
        facts["metadata_fields_missing"] = missing_metadata
        excluded = check.get("excluded", 0)
        if type(excluded) is not int or not 0 <= excluded <= 10000:
            raise ValueError("Invalid excluded count")
        facts["excluded_count"] = excluded
    data = check.get("data")
    if name == "os_and_memory" and isinstance(data, dict):
        for key in ("Version", "BuildNumber", "OSArchitecture"):
            value = data.get(key)
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9 ._-]{1,80}", value):
                facts[key] = value
    if name == "defender" and not isinstance(data, dict):
        facts["protection_fields_missing"] = 6
    if name == "defender" and isinstance(data, dict):
        missing = 0
        for key in ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled",
                    "BehaviorMonitorEnabled", "IoavProtectionEnabled", "IsTamperProtected"):
            if type(data.get(key)) is bool:
                facts[key] = data[key]
            else:
                missing += 1
        facts["protection_fields_missing"] = missing
        if data.get("AMRunningMode") in ("Normal", "Passive", "EDR Block Mode", "SxS Passive Mode"):
            facts["AMRunningMode"] = data["AMRunningMode"]
    if name == "secure_boot":
        facts["protection_fields_missing"] = 0
        if isinstance(data, dict) and type(data.get("enabled")) is bool:
            facts["enabled"] = data["enabled"]
        else:
            facts["protection_fields_missing"] = 1
    if name == "defender_exclusion_counts":
        missing_counts = 0
        for key in ("path_count", "process_count", "extension_count"):
            value = data.get(key) if isinstance(data, dict) else None
            if type(value) is int and 0 <= value <= 1_000_000:
                facts[key] = value
            else:
                missing_counts += 1
        facts["metadata_fields_missing"] = missing_counts
    if name == "bitlocker_status" or name == "firewall" and "data" in check:
        rows = data if isinstance(data, list) else [data]
        missing = 0
        for row in rows:
            if not isinstance(row, dict):
                missing += 1
                continue
            if name == "firewall":
                label, value = row.get("Name"), row.get("Enabled")
                if label not in ("Public", "Private", "Domain"):
                    missing += 1
                elif type(value) is bool:
                    facts["profile_" + label.lower()] = value
                elif value in ("True", "False"):
                    facts["profile_" + label.lower()] = value == "True"
                else:
                    missing += 1
                action = row.get("DefaultInboundAction")
                if label in ("Public", "Private", "Domain") and action in ("Block", "Allow"):
                    facts["inbound_block_" + label.lower()] = action == "Block"
                else:
                    missing += 1
            else:
                label, value = row.get("MountPoint"), row.get("ProtectionStatus")
                if not isinstance(label, str) or len(label) > 512 or value not in ("On", "Off"):
                    missing += 1
                else:
                    facts["volume_" + hashlib.sha256(label.encode()).hexdigest()[:24]] = value == "On"
        facts["protection_fields_missing"] = missing + (not rows)
    if name == "wmi_persistence_counts" and isinstance(data, dict):
        for key in ("filters", "command_consumers", "script_consumers", "bindings"):
            if type(data.get(key)) is int and 0 <= data[key] <= 1_000_000:
                facts[key] = data[key]
    return facts


def make_snapshot(collection: Any, machine_id: str, environment: str, scope_id: str,
                  current: dt.datetime | None = None) -> dict[str, Any]:
    current = current or dt.datetime.now(dt.timezone.utc)
    if not identifier(machine_id) or not identifier(scope_id):
        raise ValueError("Explicit non-secret machine and scope IDs required")
    if environment not in {"host", "vm", "wsl", "container", "unknown"}:
        raise ValueError("Invalid environment")
    if isinstance(collection, dict) and "scope_id" in collection and collection["scope_id"] != scope_id:
        raise ValueError("Collector scope does not match requested scope")
    if not isinstance(collection, dict) or type(collection.get("schema_version")) is not int or collection["schema_version"] != 1:
        raise ValueError("Unsupported collector schema")
    if collection.get("platform") not in {"macos", "windows"}:
        raise ValueError("Unsupported collector platform")
    observed = timestamp(collection.get("observed_at"))
    if not 0 <= (current - observed).total_seconds() <= 7200:
        raise ValueError("Collector is stale or from the future")
    checks = collection.get("checks")
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_CHECKS:
        raise ValueError("Missing or excessive checks")
    normalized = {}
    for check in checks:
        if not isinstance(check, dict) or not identifier(check.get("check")):
            raise ValueError("Invalid check")
        name = check["check"]
        if name.startswith("local_") and collection.get("scope_id") != scope_id:
            raise ValueError("Collector scope does not match requested scope")
        if check.get("status") not in STATUSES:
            raise ValueError("Unknown check status")
        path = check.get("path")
        key = name + (":" + hashlib.sha256(str(path).encode()).hexdigest() if path is not None else "")
        if key in normalized:
            raise ValueError("Duplicate check identity")
        collection_status = check.get("collection_status", check["status"])
        protection = check.get("protection_status", "NOT ASSESSED")
        if collection_status not in STATUSES or protection not in STATUSES:
            raise ValueError("Invalid component status")
        if isinstance(check.get("entries"), list) and any(
                isinstance(row, dict) and row.get("status") in {"NOT RUN", "PARTIAL"}
                for row in check["entries"]):
            collection_status = "PARTIAL"
        facts = _facts(check)
        if (facts.get("protection_fields_missing", 0) or facts.get("metadata_fields_missing", 0)) and collection_status == "PASS":
            collection_status = "PARTIAL"
        if collection_status not in {"NOT RUN", "NOT ASSESSED"} and name == "defender" and (not isinstance(check.get("data"), dict) or check["data"].get("AMRunningMode") != "Normal"):
            collection_status, protection = "PARTIAL", "NOT ASSESSED"
        evidence_at = check.get("observed_at")
        try:
            evidence_time = timestamp(evidence_at)
            fresh_evidence = 0 <= (current - evidence_time).total_seconds() <= 7200
        except (ValueError, TypeError):
            evidence_at, fresh_evidence = None, False
        if not fresh_evidence:
            if collection_status not in {"NOT RUN", "NOT ASSESSED"}:
                collection_status = "PARTIAL"
            if protection != "NOT RUN":
                protection = "NOT ASSESSED"
        if collection_status in {"NOT RUN", "NOT ASSESSED"}:
            protection = "NOT RUN" if collection_status == "NOT RUN" else "NOT ASSESSED"
        normalized_status = check["status"]
        if normalized_status == "PASS" and (collection_status != "PASS" or protection == "NOT RUN"):
            normalized_status = "PARTIAL"
        normalized[key] = {"status": normalized_status, "collection_status": collection_status,
                           "protection_status": protection, "facts": facts, "observed_at": evidence_at}
    architecture = collection.get("architecture", "unknown")
    if not isinstance(architecture, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", architecture):
        raise ValueError("Invalid architecture")
    collector_version = collection.get("collector_version", "legacy-1")
    if not version_label(collector_version):
        raise ValueError("Invalid collector version")
    snapshot = {"schema_version": VERSION, "kind": "pc-audit-observation",
                "machine_id": machine_id, "platform": collection["platform"],
                "architecture": architecture, "environment": environment, "scope_id": scope_id,
                "collector_version": collector_version, "observed_at": observed.isoformat(),
                "trust_assessment": "NOT ATTESTED", "checks": normalized}
    snapshot["sha256"] = digest(snapshot)
    return snapshot


def validate_snapshot(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != SNAPSHOT_KEYS:
        raise ValueError("Invalid snapshot fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != VERSION or value["kind"] != "pc-audit-observation":
        raise ValueError("Unsupported snapshot")
    if not all(identifier(value[key]) for key in ("machine_id", "scope_id")) or not version_label(value["collector_version"]):
        raise ValueError("Invalid snapshot identity")
    if value["platform"] not in {"macos", "windows"} or value["environment"] not in {"host", "vm", "wsl", "container", "unknown"}:
        raise ValueError("Invalid platform/environment")
    if not isinstance(value["architecture"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", value["architecture"]):
        raise ValueError("Invalid architecture")
    if value["trust_assessment"] != "NOT ATTESTED" or value["sha256"] != digest(value):
        raise ValueError("Invalid snapshot checksum or trust claim")
    snapshot_time = timestamp(value["observed_at"])
    if not isinstance(value["checks"], dict) or not 1 <= len(value["checks"]) <= MAX_CHECKS:
        raise ValueError("Invalid check count")
    for key, check in value["checks"].items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}(?::[0-9a-f]{64})?", key):
            raise ValueError("Invalid check key")
        if not isinstance(check, dict) or set(check) != {"status", "collection_status", "protection_status", "facts", "observed_at"}:
            raise ValueError("Invalid normalized check")
        if any(check[field] not in STATUSES for field in ("status", "collection_status", "protection_status")):
            raise ValueError("Invalid check status")
        if check["observed_at"] is not None:
            evidence_time = timestamp(check["observed_at"])
            if check["collection_status"] == "PASS" and not 0 <= (snapshot_time - evidence_time).total_seconds() <= 7200:
                raise ValueError("Stale check represented as complete")
        elif check["collection_status"] == "PASS":
            raise ValueError("Complete check has no evidence timestamp")
        if not isinstance(check["facts"], dict) or len(check["facts"]) > 1024:
            raise ValueError("Invalid fact count")
        for name, fact in check["facts"].items():
            if name == "entry_fingerprints":
                if not isinstance(fact, dict) or len(fact) > 10_000 or any(
                        not isinstance(k, str) or not isinstance(v, str) or
                        not re.fullmatch(r"[0-9a-f]{64}", k) or not re.fullmatch(r"[0-9a-f]{64}", v)
                        for k, v in fact.items()):
                    raise ValueError("Invalid entry fingerprints")
            elif not isinstance(name, str) or not identifier(name) or not _scalar(fact):
                raise ValueError("Invalid fact")


def coverage(snapshot: dict[str, Any]) -> list[str]:
    return sorted(key for key, check in snapshot["checks"].items()
                  if check["status"] in {"PARTIAL", "NOT RUN", "NOT ASSESSED"}
                  or check["collection_status"] in {"PARTIAL", "NOT RUN", "NOT ASSESSED"}
                  or check["protection_status"] == "NOT RUN")


def concerns(snapshot: dict[str, Any]) -> list[str]:
    return sorted(key for key, check in snapshot["checks"].items()
                  if check["status"] == "FAIL" or check["protection_status"] == "FAIL"
                  or any(type(value) is bool and not value for value in check["facts"].values())
                  or key.startswith("local_") and any(check["facts"].get(field, 0) > 0
                     for field in ("finding_count", "critical", "high", "medium", "suppressed_findings")))


def compare(previous: Any, current: Any, max_gap_hours: float = 36,
            clock: dt.datetime | None = None) -> dict[str, Any]:
    validate_snapshot(previous)
    validate_snapshot(current)
    if not 1 <= max_gap_hours <= 8760:
        raise ValueError("Invalid gap policy")
    clock = clock or dt.datetime.now(dt.timezone.utc)
    before, after = timestamp(previous["observed_at"]), timestamp(current["observed_at"])
    if not 0 < (after - before).total_seconds() or not 0 <= (clock - after).total_seconds() <= 7200:
        raise ValueError("Nonchronological or stale observations")
    identity = ("machine_id", "platform", "architecture", "environment", "scope_id", "collector_version")
    if any(previous[key] != current[key] for key in identity) or current["architecture"] == "unknown":
        raise ValueError("Incompatible machine, environment, scope or collector")
    old, new = previous["checks"], current["checks"]
    missing = sorted(set(old) - set(new))
    def stable(check):
        return {key: item for key, item in check.items() if key != "observed_at"}
    changed = sorted(key for key in set(old) & set(new) if stable(old[key]) != stable(new[key]))
    added = sorted(set(new) - set(old))
    old_concerns, new_concerns = set(concerns(previous)), set(concerns(current))
    input_changed = {key for key in old.keys() & new.keys() if key.startswith("local_")
                     and old[key]["facts"].get("evidence_fingerprint") != new[key]["facts"].get("evidence_fingerprint")}
    lost = sorted(set(missing) | {key for key in old.keys() & new.keys()
                  if old[key]["collection_status"] == "PASS" and new[key]["collection_status"] != "PASS"
                  or old[key]["protection_status"] in {"PASS", "FAIL"}
                  and new[key]["protection_status"] not in {"PASS", "FAIL"}
                  or set(old[key]["facts"]) - set(new[key]["facts"])
                  or key in old_concerns and key not in new_concerns and new[key]["collection_status"] != "PASS"
                  or old[key]["observed_at"] is not None and new[key]["observed_at"] is not None
                  and timestamp(new[key]["observed_at"]) < timestamp(old[key]["observed_at"])})
    gap = (after - before).total_seconds() > max_gap_hours * 3600
    reasons = []
    if added or changed or missing:
        reasons.append("observations_changed; requires interpretation")
    if lost:
        reasons.append("coverage_lost; disappearance never closes a finding")
    if input_changed:
        reasons.append("local_evidence_changed; prior findings require reassessment")
    if new_concerns - old_concerns:
        reasons.append("new_observed_concern; not proof of compromise")
    if gap:
        reasons.append("run_gap_exceeds_policy; not evidence of continuous monitoring")
    unresolved_local = {key for key in old_concerns - new_concerns if key.startswith("local_")}
    return {"status": "PARTIAL" if coverage(current) or lost or gap or new_concerns or input_changed or unresolved_local else "PASS",
            "verdict": "NOT ASSESSED", "notify": bool(reasons), "reasons": reasons,
            "added": added, "changed": changed, "missing": missing, "coverage_lost": lost,
            "current_gaps": coverage(current), "current_concerns": sorted(new_concerns),
            "persistent_concerns": sorted(new_concerns & old_concerns),
            "inputs_not_comparable": sorted(input_changed),
            "unverified_prior_concerns": sorted(old_concerns & (set(lost) | input_changed) | unresolved_local),
            "observed_improvements": sorted(old_concerns - new_concerns - set(lost) - input_changed - unresolved_local),
            "run_gap_hours": (after - before).total_seconds() / 3600,
            "meaning": "Local observations only; no findings auto-closed, no consent or host attestation",
            "execution": "NONE"}


def write_snapshot(path: Path, value: dict[str, Any]) -> None:
    """Exclusive create only; parent must already be an approved local directory."""
    validate_snapshot(value)
    if not path.is_absolute() or private_path(str(path)) or ".." in path.parts:
        raise ValueError("Exact non-sensitive absolute output required")
    # exact_parent performs both lexical validation and no-follow/reparse checks;
    # do not stat an unvalidated Windows DOS-device or ADS path first.
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, indent=2) + "\n").encode()
    if len(payload) > 1_048_576:
        raise ValueError("Snapshot exceeds local storage limit")
    with exact_parent(path) as (parent, absolute):
        descriptor = os.open(absolute.name if parent is not None else absolute,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
                             0o600, dir_fd=parent)
    with os.fdopen(descriptor, "wb") as output:
        verify_regular_descriptor(output.fileno(), absolute)
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    snap = commands.add_parser("snapshot", help="Normalize supplied collector JSON and explicitly save a new local file")
    snap.add_argument("--input", type=Path, required=True)
    snap.add_argument("--machine-id", required=True)
    snap.add_argument("--environment", required=True, choices=["host", "vm", "wsl", "container", "unknown"])
    snap.add_argument("--scope-id", required=True)
    snap.add_argument("--output", type=Path, required=True)
    diff = commands.add_parser("compare", help="Read two exact snapshots; never modify or auto-accept a baseline")
    diff.add_argument("--previous", type=Path, required=True)
    diff.add_argument("--current", type=Path, required=True)
    diff.add_argument("--max-gap-hours", type=float, default=36)
    args = parser.parse_args(argv)
    try:
        if args.command == "snapshot":
            value = make_snapshot(read_plan(args.input, max_bytes=4_194_304), args.machine_id, args.environment, args.scope_id)
            write_snapshot(args.output, value)
            result = {"status": "PASS", "snapshot": display(str(args.output)), "sha256": value["sha256"],
                      "meaning": "Explicit local observation saved; not trusted baseline or remediation consent"}
        else:
            result = compare(read_plan(args.previous), read_plan(args.current), args.max_gap_hours)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        print(json.dumps({"status": "FAIL", "reason": error_code(exc), "execution": "NONE"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
