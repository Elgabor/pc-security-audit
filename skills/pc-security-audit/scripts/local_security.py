#!/usr/bin/env python3
"""Offline skill triage, local OSV-cache matching and Cisco report ingestion.

No network, installations, discovered-code execution, remediation or session reads.
Only an explicitly selected source directory or bounded regular JSON is read.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time

_spec = importlib.util.spec_from_file_location("pc_audit_local", Path(__file__).resolve().with_name("audit.py"))
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)

MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_FINDINGS = 128, 262144, 2097152, 200
EXTENSIONS = {"", ".md", ".py", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".pl",
              ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mdx", ".html", ".json", ".yaml", ".yml", ".toml", ".txt"}
STATE_NAMES = {"projects", "todos", "plans", "shell-snapshots", "file-history", "archived_sessions",
               "settings.json", "settings.local.json", "config.toml", "hosts.yml", "mcp.json", ".mcp.json"}
RULES = [(name, re.compile(pattern, re.I)) for name, pattern in [
    ("instruction_override", r"\bignore\s+(?:all\s+)?(?:previous|system|developer)\s+instructions\b"),
    ("download_to_shell", r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,200}\|\s*(?:sudo(?:\s+-\S+)*\s+)?(?:bash|sh|zsh|python[0-9.]*\b(?!\s+-m\s+json\.tool\b)|iex|Invoke-Expression)\b|\b(?:bash|sh|zsh|source)\s*<\(\s*(?:curl|wget)\b|\b(?:ba|z)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b|\biex\s*\(\s*(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b"),
    ("shell_interpolation", r"\bshell\s*=\s*True\b|\bInvoke-Expression\b|\beval\s*(?:\(|[\"'$`])|\bos\.system\s*\("),
    ("sensitive_store_access", r"\b(?:cat|Get-Content|read_file)\b[^\n]{0,100}(?:\.env\b|\.ssh/|keychain|cookies\.sqlite)"),
    ("approval_bypass", r"\b(?:bypass|disable|skip)\s+(?:all\s+)?(?:approvals?|permission\s+checks)\b"),
    ("invisible_controls", r"[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufe00-\ufe0f\ufeff\ufff9-\ufffb\U000e0000-\U000e007f\U000e0100-\U000e01ef]"),
]]


def sensitive_source_name(name):
    """Exclude credential-like names before reading or fingerprinting them."""
    lower = name.casefold()
    return (audit.private_path(name) or lower in STATE_NAMES or "secret" in lower
            or lower.lstrip(".").startswith(("token", "credential")) and Path(lower).suffix in {"", ".json", ".yaml", ".yml", ".toml", ".txt"}
            or bool(re.match(r"\.?tokens?(?:$|[_.-])|\.?credentials?(?:$|[_.-])|client_secret|service[-_]account", lower)))


def invisible_signal(line, pattern):
    for match in pattern.finditer(line):
        if ord(match[0]) in {0xFE0E, 0xFE0F, 0x200D} and any(
                0x2300 <= ord(c) <= 0x27FF or 0x1F000 <= ord(c) <= 0x1FAFF
                for c in line[max(0, match.start() - 2):match.end() + 2]):
            continue
        return True
    return False


def stamp(value, current=None, max_hours=24):
    if not isinstance(value, str):
        raise ValueError("timestamp_required")
    observed = dt.datetime.fromisoformat(value)
    current = current or dt.datetime.now(dt.timezone.utc)
    if observed.tzinfo is None or not 0 <= (current - observed).total_seconds() <= max_hours * 3600:
        raise ValueError("stale_or_future_evidence")
    return observed


def result(kind, **fields):
    return {"schema_version": 1, "kind": kind, "observed_at": audit.now(),
            "verdict": "NOT ASSESSED", "execution": "NONE", "network_requests": 0, **fields}


def with_collector(value, scope_id=None):
    """Allow existing snapshot machinery to retain only whitelisted counters."""
    names = {"local-skill-triage": "local_skill_triage", "cisco-report-assessment": "local_cisco_report",
             "offline-package-advisories": "local_package_advisories"}
    if value["kind"] not in names:
        return value
    if not isinstance(scope_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", scope_id):
        raise ValueError("invalid_scope_id")
    counters = {k: value[k] for k in ("files_read", "bytes_read", "coverage_gaps", "scanned_skills",
                                     "suppressed_findings", "packages_assessed", "advisory_records", "cache_age_minutes") if k in value}
    counters["finding_count"] = len(value.get("findings", []))
    counters["evidence_fingerprint"] = value.get("evidence_fingerprint")
    counters.update({k.lower(): v for k, v in value.get("severity_counts", {}).items()})
    evidence = value.get("evidence_observed_at", value["observed_at"])
    check = {"check": names[value["kind"]], "status": value["status"],
             "collection_status": "NOT RUN" if value["status"] == "NOT RUN" else "PARTIAL" if counters.get("coverage_gaps", 0) else "PASS",
             "observed_at": evidence, "data": counters}
    value.update(collector_version="local-security-3", architecture=platform.machine(),
                 platform={"Darwin": "macos", "Windows": "windows"}.get(platform.system(), "unsupported"), checks=[check])
    if scope_id is not None:
        value["scope_id"] = scope_id
    return value


def scan_skill(root: Path):
    root = root.absolute()
    if ".." in root.parts or any(part.casefold() in STATE_NAMES | {".git"} for part in root.parts):
        raise ValueError("state_is_not_skill_source")
    if root.name.casefold() in {".claude", ".codex", ".config", ".agents", ".pi", "library", "plugins", "skills"}:
        raise ValueError("exact_skill_root_required")
    # Reuse the existing broad-root/private-path rejection before content reads.
    audit.inventory(root, max_entries=1, max_depth=0)
    if os.name != "posix":
        return result("local-skill-triage", status="NOT RUN", reason="safe_descriptor_walk_unavailable")
    findings, gaps, files, total, examined = [], 0, 0, 0, 0
    file_signatures, entry_signatures = [], []
    deadline = time.monotonic() + 5
    with audit.exact_parent(root) as (parent, exact):
        descriptor = os.open(exact.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        entrypoint = os.stat("SKILL.md", dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISREG(entrypoint.st_mode) or entrypoint.st_nlink != 1:
            raise ValueError("regular_skill_entrypoint_required")
    except (OSError, ValueError):
        os.close(descriptor)
        raise ValueError("regular_skill_entrypoint_required") from None
    device = os.fstat(descriptor).st_dev

    def walk(fd, relative, depth):
        nonlocal gaps, files, total, examined
        with os.scandir(fd) as entries:
            class Entrypoint:
                name = "SKILL.md"
                def stat(self, **_kwargs):
                    return os.stat(self.name, dir_fd=fd, follow_symlinks=False)
            def ordered():
                if depth == 0:
                    yield Entrypoint()
                for item in entries:
                    if depth != 0 or item.name != "SKILL.md":
                        yield item
            for entry in ordered():
                if examined >= 1024 or files >= MAX_FILES or total >= MAX_TOTAL_BYTES or time.monotonic() >= deadline or len(findings) >= MAX_FINDINGS:
                    gaps += 1
                    return
                examined += 1
                rel = relative / entry.name
                if audit.private_path(str(root / rel)) or sensitive_source_name(entry.name):
                    gaps += 1
                    continue
                child = None
                try:
                    info = entry.stat(follow_symlinks=False)
                    entry_signatures.append((rel.as_posix(), stat.S_IFMT(info.st_mode), info.st_size, info.st_mtime_ns))
                    if entry.name in {".git", "__pycache__", ".venv", "node_modules"}:
                        gaps += 1
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if depth >= 5 or info.st_dev != device:
                            gaps += 1
                            continue
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        opened = os.fstat(child)
                        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                            raise ValueError("directory_changed")
                        walk(child, rel, depth + 1)
                    elif stat.S_ISREG(info.st_mode) and Path(entry.name).suffix.lower() in EXTENSIONS:
                        if info.st_size > min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total):
                            gaps += 1
                            continue
                        child = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                        opened = audit.verify_regular_descriptor(child, root / rel)
                        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                            raise ValueError("file_changed")
                        chunks, size = [], 0
                        cap = min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total)
                        while size <= cap:
                            chunk = os.read(child, min(8192, cap + 1 - size))
                            if not chunk:
                                break
                            chunks.append(chunk)
                            size += len(chunk)
                        total += size
                        if size > cap:
                            gaps += 1
                            continue
                        try:
                            content = b"".join(chunks)
                            text = content.decode("utf-8-sig")
                        except UnicodeError:
                            gaps += 1
                            continue
                        files += 1
                        file_signatures.append((rel.as_posix(), hashlib.sha256(content).hexdigest()))
                        for line_number, line in enumerate(text.split("\n"), 1):
                            if time.monotonic() >= deadline or len(findings) >= MAX_FINDINGS:
                                gaps += 1
                                return
                            for rule, pattern in RULES:
                                matched = invisible_signal(line, pattern) if rule == "invisible_controls" else pattern.search(line)
                                if matched:
                                    findings.append({"file": audit.display(rel.as_posix()), "line": line_number,
                                                     "rule": rule, "classification": "REVIEW INDICATOR"})
                                    if len(findings) >= MAX_FINDINGS:
                                        gaps += 1
                                        break
                    else:
                        gaps += 1
                except (OSError, ValueError):
                    gaps += 1
                finally:
                    if child is not None:
                        os.close(child)
    try:
        walk(descriptor, Path(), 0)
    finally:
        os.close(descriptor)
    return result("local-skill-triage", status="PARTIAL",
                  files_read=files, bytes_read=total, coverage_gaps=gaps, findings=findings,
                  evidence_fingerprint=hashlib.sha256(json.dumps({"contents": sorted(file_signatures), "entries": sorted(entry_signatures),
                      "engine": {"rules": [(name, rule.pattern) for name, rule in RULES], "extensions": sorted(EXTENSIONS),
                                 "excluded": sorted(STATE_NAMES), "limits": [MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_FINDINGS, 1024, 5]}}).encode()).hexdigest(),
                  engine="bounded local indicators; not Cisco Skill Scanner",
                  rules_checked=[name for name, _ in RULES],
                  meaning="No indicators is not a clean verdict. Quoted defensive examples may match; corroborate before intervention")


def cisco_report(value, current=None):
    if not isinstance(value, dict):
        raise ValueError("invalid_report")
    rows = value.get("results", [value])
    if not isinstance(rows, list) or not 1 <= len(rows) <= 128:
        raise ValueError("invalid_report_results")
    counts = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    gaps, suppressed, analyzers, evidence_times = 0, 0, set(), []
    all_findings, identities, coverage_identity = [], [], []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("findings"), list) or len(row["findings"]) > 2048:
            raise ValueError("invalid_scan_result")
        evidence_times.append(stamp(row.get("timestamp"), current, 2))
        gaps += sum(key not in row for key in ("skill_name", "skill_path", "scan_metadata", "findings_count",
                                                "analyzers_failed", "suppressed_findings"))
        used = row.get("analyzers_used")
        if not isinstance(used, list) or not used or len(used) > 64:
            gaps += 1
        else:
            for name in used:
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name):
                    raise ValueError("invalid_analyzer_name")
                analyzers.add(name)
        failed = row.get("analyzers_failed", [])
        hidden = row.get("suppressed_findings", [])
        if not isinstance(failed, list) or not isinstance(hidden, list) or len(failed) > 64 or len(hidden) > 2048:
            raise ValueError("invalid_analyzer_coverage")
        gaps += len(failed)
        suppressed += len(hidden)
        coverage_identity.append({"skill_name": row.get("skill_name"), "skill_path": row.get("skill_path"),
                                  "scan_metadata": row.get("scan_metadata"), "failed": failed, "suppressed": hidden})
        if row.get("findings_count", len(row["findings"])) != len(row["findings"]):
            gaps += 1
        all_findings.extend(row["findings"])
    cross = value.get("cross_skill_findings", [])
    if "results" in value:
        gaps += sum(key not in value for key in ("summary", "cross_skill_findings"))
    if not isinstance(cross, list) or len(cross) > 2048:
        raise ValueError("invalid_cross_skill_findings")
    all_findings.extend(cross)
    for finding in all_findings:
        severity = finding.get("severity") if isinstance(finding, dict) else None
        if isinstance(severity, str) and severity.upper() in counts:
            counts[severity.upper()] += 1
            if not audit.plain_text(finding.get("id"), 256):
                gaps += 1
            identities.append({key: finding.get(key) for key in ("id", "severity", "category", "file_path", "line_number")})
        else:
            gaps += 1
    summary = value.get("summary", {})
    if not isinstance(summary, dict):
        raise ValueError("invalid_summary")
    skipped = summary.get("skills_skipped", [])
    if "results" in value and "skills_skipped" not in summary:
        gaps += 1
    if not isinstance(skipped, list) or len(skipped) > 2048:
        raise ValueError("invalid_skipped_skills")
    gaps += len(skipped)
    return result("cisco-report-assessment", status="FAIL" if counts["HIGH"] or counts["CRITICAL"] else
                  "PARTIAL",
                  evidence_observed_at=min(evidence_times).isoformat(), scanned_skills=len(rows),
                  severity_counts=counts, coverage_gaps=gaps, suppressed_findings=suppressed,
                  evidence_fingerprint=hashlib.sha256(json.dumps({"findings": identities, "analyzers": sorted(analyzers),
                                      "coverage": coverage_identity, "skipped": skipped}, sort_keys=True).encode()).hexdigest(),
                  analyzers_used=sorted(analyzers), input_provenance="supplied local export; not attested",
                  meaning="Coverage/provenance are not attested; no export earns a clean verdict. No raw findings, paths or snippets emitted")


def package_name(name, ecosystem):
    pattern = r"[A-Za-z0-9][A-Za-z0-9._~+/-]{0,239}" if ecosystem == "Go" else r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9][A-Za-z0-9_.-]{0,213}"
    if not isinstance(name, str) or not re.fullmatch(pattern, name):
        raise ValueError("invalid_package_name")
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


def semver(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})", value):
        raise ValueError("unsupported_version")
    return tuple(map(int, value.split(".")))


def affected(version, row, ecosystem="npm"):
    versions = row.get("versions", [])
    if not isinstance(versions, list) or len(versions) > 20000 or any(not isinstance(x, str) or len(x) > 100 for x in versions):
        return None
    if version in versions:
        return True
    ranges = row.get("ranges", [])
    if not isinstance(ranges, list) or len(ranges) > 128:
        return None
    if not ranges:
        return False if versions and ecosystem == "npm" else None
    try:
        if ecosystem == "Go" and version.startswith("v"):
            version = version[1:]
        current = semver(version)
        unknown = False
        any_match = False
        for item in ranges:
            if not isinstance(item, dict) or item.get("type") != "SEMVER":
                unknown = True
                continue
            events = item.get("events")
            if not isinstance(events, list) or not 1 <= len(events) <= 256:
                return None
            active, previous, matched = False, None, False
            for event in events:
                if not isinstance(event, dict) or len(event) != 1:
                    return None
                key, text = next(iter(event.items()))
                if key not in {"introduced", "fixed", "last_affected"}:
                    return None
                bound = (0, 0, 0) if key == "introduced" and text == "0" else semver(text)
                if previous is not None and bound < previous:
                    return None
                previous = bound
                if key == "introduced":
                    if active:
                        return None
                    active = True
                    lower = bound
                else:
                    if not active:
                        return None
                    matched |= lower <= current and (current < bound if key == "fixed" else current <= bound)
                    active = False
            if active:
                matched |= lower <= current
            any_match |= matched
        return True if any_match else None if unknown else False
    except (ValueError, TypeError):
        return None


def inventory_packages(value, gaps=None):
    if not isinstance(value, dict):
        raise ValueError("invalid_inventory")
    if "lockfileVersion" in value:
        if value["lockfileVersion"] not in (2, 3) or not isinstance(value.get("packages"), dict) or len(value["packages"]) > 4096:
            raise ValueError("unsupported_lockfile")
        rows = []
        for path, item in value["packages"].items():
            if not isinstance(path, str) or not isinstance(item, dict):
                raise ValueError("invalid_lockfile_entry")
            if not path:
                continue
            if item.get("link") is True or "node_modules/" not in path:
                if gaps is not None:
                    gaps.append("workspace_or_link_not_assessed")
                continue
            name = item.get("name") or path.rsplit("node_modules/", 1)[-1]
            rows.append({"ecosystem": "npm", "name": name, "version": item.get("version")})
    else:
        if type(value.get("schema_version")) is not int or value["schema_version"] != 1 or not isinstance(value.get("packages"), list) or len(value["packages"]) > 4096:
            raise ValueError("invalid_package_inventory")
        rows = value["packages"]
    clean = []
    for row in rows:
        if not isinstance(row, dict) or row.get("ecosystem") not in {"npm", "PyPI", "Go"}:
            raise ValueError("unsupported_ecosystem")
        name = package_name(row.get("name"), row["ecosystem"])
        version = row.get("version")
        if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9.+_-]{1,100}", version):
            raise ValueError("invalid_version")
        clean.append({"ecosystem": row["ecosystem"], "name": name, "version": version})
    return [dict(ecosystem=eco, name=name, version=version) for eco, name, version in
            sorted({(p["ecosystem"], p["name"], p["version"]) for p in clean})]


def audit_packages(inventory, cache, current=None, max_cache_age_hours=24):
    if type(max_cache_age_hours) is not int or not 1 <= max_cache_age_hours <= 720:
        raise ValueError("invalid_cache_age_policy")
    inventory_gaps = []
    packages = inventory_packages(inventory, inventory_gaps)
    if not isinstance(cache, dict) or type(cache.get("schema_version")) is not int or cache["schema_version"] != 1:
        raise ValueError("invalid_advisory_cache")
    fetched = stamp(cache.get("fetched_at"), current, max_cache_age_hours)
    age_seconds = ((current or dt.datetime.now(dt.timezone.utc)) - fetched).total_seconds()
    age_minutes = int(age_seconds // 60)
    advisories = cache.get("advisories")
    if not isinstance(advisories, list) or len(advisories) > 4096:
        raise ValueError("invalid_advisory_cache")
    findings, gaps, comparisons = [], len(inventory_gaps) + int(age_seconds > 86400), 0
    declared = cache.get("queried_packages")
    covered = set()
    if isinstance(declared, list) and len(declared) <= 4096:
        for item in declared:
            try:
                rows = inventory_packages({"schema_version": 1, "packages": [item]})
                covered.update((row["ecosystem"], row["name"], row["version"]) for row in rows)
            except (ValueError, TypeError):
                gaps += 1
    else:
        gaps += 1
    gaps += sum((p["ecosystem"], p["name"], p["version"]) not in covered for p in packages)
    deadline = time.monotonic() + 5
    index = {}
    for package in packages:
        index.setdefault((package["ecosystem"], package["name"]), []).append(package)
    def finish():
        return result("offline-package-advisories", status="FAIL" if findings else "PARTIAL" if gaps or not packages else "PASS",
                      packages_assessed=len(packages), advisory_records=len(advisories), coverage_gaps=gaps,
                      evidence_fingerprint=hashlib.sha256(json.dumps({"inventory": packages, "advisories": advisories, "queried_packages": declared}, sort_keys=True).encode()).hexdigest(),
                      evidence_observed_at=fetched.isoformat(), cache_observed_at=fetched.isoformat(), cache_age_minutes=age_minutes, findings=findings,
                      meaning="Matching only the supplied local cache; freshness is declared, not attested. No finding does not establish absence of vulnerabilities")
    for advisory in advisories:
        if not isinstance(advisory, dict) or not isinstance(advisory.get("affected"), list) or len(advisory["affected"]) > 512:
            gaps += 1
            continue
        if advisory.get("withdrawn"):
            continue
        name = advisory.get("id", "")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9:_.-]{1,100}", name):
            gaps += 1
            continue
        for row in advisory["affected"]:
            if time.monotonic() >= deadline or comparisons >= 10000:
                gaps += 1
                return finish()
            if not isinstance(row, dict) or not isinstance(row.get("package"), dict):
                gaps += 1
                continue
            p = row["package"]
            ecosystem = p.get("ecosystem")
            if ecosystem not in {"npm", "PyPI", "Go"}:
                if isinstance(ecosystem, str) and ecosystem.casefold() in {"npm", "pypi", "go"}:
                    gaps += 1
                continue
            try:
                affected_name = package_name(p.get("name"), ecosystem)
            except ValueError:
                gaps += 1
                continue
            for package in index.get((ecosystem, affected_name), []):
                comparisons += 1
                if comparisons > 10000 or time.monotonic() >= deadline:
                    gaps += 1
                    return finish()
                outcome = affected(package["version"], row, ecosystem)
                if outcome is None:
                    gaps += 1
                elif outcome:
                    if len(findings) >= MAX_FINDINGS:
                        gaps += 1
                        continue
                    findings.append({"advisory_id": name, "ecosystem": package["ecosystem"],
                                     "package": audit.display(package["name"]), "version": package["version"]})
    return finish()


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan-skill"); scan.add_argument("--root", type=Path, required=True)
    cisco = sub.add_parser("cisco-report"); cisco.add_argument("input", type=Path)
    packages = sub.add_parser("packages"); packages.add_argument("--inventory", type=Path, required=True)
    packages.add_argument("--advisories", type=Path, required=True)
    packages.add_argument("--max-cache-age-hours", type=int, default=24)
    for command in (scan, cisco, packages):
        command.add_argument("--scope-id", required=True, help="Agreed nonsecret scope alias; reuse it for periodic snapshots")
    args = parser.parse_args(argv)
    try:
        if args.command == "scan-skill":
            value = scan_skill(args.root)
        elif args.command == "cisco-report":
            value = cisco_report(audit.read_plan(args.input))
        else:
            value = audit_packages(audit.read_plan(args.inventory), audit.read_plan(args.advisories),
                                   max_cache_age_hours=args.max_cache_age_hours)
        value = with_collector(value, args.scope_id)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        kind = {"scan-skill": "local-skill-triage", "cisco-report": "cisco-report-assessment", "packages": "offline-package-advisories"}[args.command]
        value = result(kind, status="NOT RUN", reason="invalid_inaccessible_or_stale_input", coverage_gaps=1)
        # Keep malformed scope aliases out of snapshot-compatible observations.
        if re.fullmatch(r"[A-Za-z0-9_-]{1,80}", args.scope_id):
            value = with_collector(value, args.scope_id)
    print(json.dumps(value, ensure_ascii=False, allow_nan=False))
    return 1 if value["status"] == "FAIL" else 2 if value["status"] in {"PARTIAL", "NOT RUN"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
