#!/usr/bin/env python3
"""Bounded metadata collection and plan validation; no remediation or shell eval.

Only fixed native commands are run. Discovered files are never opened/executed.
Output is local JSON on stdout. Python 3.11+; standard library only.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time
import unicodedata
from typing import Any

MAX_OUTPUT = 262_144
COLLECTOR_VERSION = "0.3.0"
SECRET_COMPONENTS = {
    ".ssh", ".aws", ".azure", ".kube", ".gnupg", "keychains", "keychain",
    "credentials", "credential", "cookies", "sessions", "sessionstore",
    "session storage", "local storage", "login data", "web data", "auth.json",
    "authentication.json", ".netrc", ".npmrc", ".pypirc", "secrets", "tokens",
    "sessionstore-backups", "key4.db", "logins.json", "cookies.sqlite",
    ".zsh_history", ".bash_history", ".python_history", ".git-credentials",
    ".credentials.json", "local state", "history.jsonl", "history.sqlite",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "user data",
    "history", "history.db", "places.sqlite",
}
SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx", ".mobileprovision"}
ACTION_KEYS = {
    "id", "category", "targets", "operation", "reason", "evidence",
    "preconditions", "risk", "rollback", "verification", "stop_if", "depends_on",
}
PLAN_KEYS = {"schema_version", "audit_id", "revision", "platform", "created_at", "scope", "actions"}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def private_path(value: str) -> bool:
    parts = re.split(r"[\\/]", value.casefold())
    for index, part in enumerate(parts):
        base = re.sub(r"-(?:journal|wal|shm)$", "", part)
        if base in SECRET_COMPONENTS or base.startswith(".env") or base.endswith(tuple(SECRET_SUFFIXES)):
            return True
        if base.endswith(("_history", "_history.txt")):
            return True
        if base.startswith("sessionstore"):
            return True
        if part == ".claude" and index + 1 < len(parts) and parts[index + 1] == "projects":
            return True
        if part == "microsoft" and index + 1 < len(parts) and parts[index + 1] in {"protect", "vault", "crypto"}:
            return True
    return False


def display(value: str, home: Path | None = None) -> str:
    """Minimize obvious private strings, not a general-purpose secret detector."""
    home_text = str(home or Path.home())
    value = value.replace(home_text, "<HOME>")
    value = "".join("?" if unicodedata.category(c).startswith("C") else c for c in value)
    value = re.sub(r"(?i)(bearer\s+|(?:token|password|api[_-]?key|secret)=)\S+",
                   r"\1<REDACTED>", value)
    value = re.sub(r"\b(?:sk-proj-|sk-ant-|ghp_|github_pat_)[A-Za-z0-9_-]+", "<REDACTED>", value)
    return value


def plain_text(value: Any, maximum: int = 4096) -> bool:
    """Single-line, canonical, visible text; never normalize an action silently."""
    return (isinstance(value, str) and 0 < len(value) <= maximum and bool(value.strip())
            and unicodedata.normalize("NFC", value) == value
            and not any(unicodedata.category(c).startswith("C") for c in value))


def record(check: str, status: str, **data: Any) -> dict[str, Any]:
    return {"check": check, "status": status, "observed_at": now(), **data}


def run_bounded(argv: list[str], timeout: float = 10) -> subprocess.CompletedProcess:
    """Bound both pipes and waits for a fixed native command; never use Popen's
    context manager because its implicit final wait has no deadline.
    """
    output = bytearray()
    counts = {"stdout": 0, "stderr": 0}
    timed_out = limited = unreaped = False
    deadline = time.monotonic() + timeout
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL,
                             env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, "stdout")
            selector.register(child.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(remaining):
                    data = os.read(key.fileobj.fileno(), 8192)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    counts[key.data] += len(data)
                    if counts[key.data] > MAX_OUTPUT:
                        limited = True
                        break
                    if key.data == "stdout":
                        output.extend(data)
                if limited:
                    break
        if (timed_out or limited) and child.poll() is None:
            child.kill()
        try:
            child.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
    finally:
        try:
            if child.poll() is None:
                try:
                    child.kill()
                except OSError:
                    pass
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    unreaped = True
        finally:
            child.stdout.close()
            child.stderr.close()
    result = subprocess.CompletedProcess(argv, child.returncode, bytes(output), b"")
    result.timed_out, result.output_limited, result.unreaped = timed_out, limited, unreaped
    return result


def native(check: str, argv: list[str], timeout: int = 10) -> dict[str, Any]:
    """Do not return native error bodies: they can echo unanticipated secrets."""
    if not Path(argv[0]).is_file():
        return record(check, "NOT RUN", reason="native_command_missing", command=argv[0])
    try:
        result = run_bounded(argv, timeout)
    except subprocess.TimeoutExpired:
        return record(check, "NOT RUN", reason="timeout", timeout_seconds=timeout)
    except OSError as exc:
        return record(check, "NOT RUN", reason=type(exc).__name__)
    if getattr(result, "unreaped", False):
        return record(check, "NOT RUN", reason="collector_child_exit_unverified")
    if getattr(result, "timed_out", False):
        return record(check, "NOT RUN", reason="timeout", timeout_seconds=timeout)
    if getattr(result, "output_limited", False) or len(result.stdout) > MAX_OUTPUT:
        return record(check, "PARTIAL", reason="output_limit", limit_bytes_per_stream=MAX_OUTPUT)
    # Protection states are separate from whether the query completed. Only
    # match known summaries; never expose arbitrary failure bodies.
    protection_patterns = {
        "gatekeeper": rb"^assessments (enabled|disabled)$",
        "sip": rb"^system integrity protection status: (enabled|disabled)\.$",
        "filevault": rb"^filevault is (on|off)\.$",
        "firewall": rb"^firewall is (enabled|disabled)\.\s*\(state = [012]\)$",
    }
    allowed_codes = (0, 1) if check == "gatekeeper" else (0,)
    if check in protection_patterns and result.returncode in allowed_codes:
        summary = result.stdout.strip().lower()
        match = re.fullmatch(protection_patterns[check], summary)
        if match:
            enabled = match[1] in (b"enabled", b"on")
            if check == "gatekeeper" and enabled and result.returncode != 0:
                return record(check, "PARTIAL", collection_status="PASS", protection_status="NOT RUN",
                              reason="contradictory_protection_exit_code")
            if check == "firewall" and enabled != (b"state = 0" not in summary):
                return record(check, "PARTIAL", collection_status="PASS", protection_status="NOT RUN",
                              reason="contradictory_protection_summary")
            status = "PASS" if enabled else "FAIL"
            return record(check, status, collection_status="PASS", protection_status=status,
                          enabled=enabled, output=summary.decode(), meaning="Observed protection state; not an overall safety verdict")
        if result.returncode == 0:
            return record(check, "PARTIAL", collection_status="PASS", protection_status="NOT RUN",
                          reason="unrecognized_or_transitioning_protection_state")
    if result.returncode:
        return record(check, "NOT RUN", reason="native_command_failed_or_access_denied",
                      exit_code=result.returncode)
    if len(result.stdout) > MAX_OUTPUT:
        return record(check, "PARTIAL", reason="output_limit", bytes_received=len(result.stdout))
    output = display(result.stdout.decode("utf-8", "replace"))
    if len(output) > 12_000:
        return record(check, "PARTIAL", output=output[:12_000], reason="display_limit",
                      meaning="bounded sample only; omitted rows are not assessed")
    return record(check, "PASS", output=output,
                  meaning="command completed; interpretation of protection state still required")


NIST_PREFERENCES = {
    "firewall_stealth": ("com.apple.security.firewall", "EnableStealthMode",
                         "system_settings_firewall_stealth_mode_enable", None),
    "screen_lock_password": ("com.apple.screensaver", "askForPassword",
                             "system_settings_screensaver_password_enforce", None),
    "screen_lock_grace": ("com.apple.screensaver", "askForPasswordDelay",
                          "system_settings_screensaver_ask_for_password_delay_enforce", 5),
}


def native_preference(check: str, firewall_state: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read three fixed nonsecret preferences; never execute downloaded rule code."""
    domain, key, rule, maximum = NIST_PREFERENCES[check]
    base = {"reference_rule": rule, "assessment_scope": "selected observed setting, not runtime enforcement",
            "method": "native_firewall_query" if check == "firewall_stealth" else "managed_user_defaults"}
    program = "/usr/libexec/ApplicationFirewall/socketfilterfw" if check == "firewall_stealth" else "/usr/bin/osascript"
    if not Path(program).is_file():
        return record(check, "NOT RUN", reason="native_command_missing", **base)
    # Domain/key come only from the fixed table; no caller-supplied code or paths.
    script = ('ObjC.import("Foundation"); var d=$.NSUserDefaults.alloc.initWithSuiteName('
              + json.dumps(domain) + '); function val(k){var v=ObjC.unwrap(d.objectForKey(k));'
              + 'return v === undefined ? null : v;} JSON.stringify({value:val(' + json.dumps(key)
              + '),forced:d.objectIsForcedForKeyInDomain(' + json.dumps(key) + ',' + json.dumps(domain)
              + ') === true,password:val("askForPassword"),password_forced:d.objectIsForcedForKeyInDomain("askForPassword",'
              + json.dumps(domain) + ') === true})')
    try:
        argv = [program, "--getstealthmode"] if check == "firewall_stealth" else [program, "-l", "JavaScript", "-e", script]
        result = run_bounded(argv, 8)
        if result.returncode or any(getattr(result, x, False) for x in ("timed_out", "output_limited", "unreaped")):
            return record(check, "NOT RUN", reason="native_preference_unavailable", **base)
        if check == "firewall_stealth":
            summary = result.stdout.strip().lower()
            match = re.fullmatch(rb"firewall stealth mode is (on|off)\.?|stealth mode (enabled|disabled)\.?", summary)
            value = next((part in (b"on", b"enabled") for part in match.groups() if part), None) if match else None
            prerequisite = firewall_state if firewall_state is not None else native("firewall", [program, "--getglobalstate"])
            trusted = prerequisite.get("enabled") is True and prerequisite.get("protection_status") == "PASS"
        else:
            observed = json.loads(result.stdout)
            if not isinstance(observed, dict):
                raise ValueError("invalid_preference_shape")
            value = observed.get("value")
            trusted = observed.get("forced") is True
            if maximum is not None:
                password = observed.get("password")
                trusted &= (observed.get("password_forced") is True and type(password) in (bool, int) and password == 1)
    except (OSError, ValueError, RecursionError):
        return record(check, "NOT RUN", reason="native_preference_unavailable", **base)
    valid = (type(value) is bool or type(value) is int and value in (0, 1)) if maximum is None else type(value) is int and 0 <= value <= 86400
    if not valid:
        return record(check, "NOT RUN", reason="preference_unset_or_unrecognized", **base)
    meets = bool(value) if maximum is None else value <= maximum
    status = ("PASS" if meets else "FAIL") if trusted else "PARTIAL"
    data = {"meets_baseline": meets} if trusted else {"reason": "effective_setting_or_prerequisite_unverified"}
    if maximum is not None:
        data.update(seconds=value, recommended_maximum_seconds=maximum)
    return record(check, status, collection_status="PASS", protection_status=status if trusted else "NOT ASSESSED", **data, **base)


def metadata(path: Path, info: os.stat_result | None = None) -> dict[str, Any]:
    info = info if info is not None else path.lstat()
    identity = {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size,
                "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns, "mode": info.st_mode}
    reparse = bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return {"name": display(path.name), "path": display(str(path)),
            "kind": "symlink" if stat.S_ISLNK(info.st_mode) or reparse else
                    "directory" if stat.S_ISDIR(info.st_mode) else
                    "file" if stat.S_ISREG(info.st_mode) else "other",
            "logical_bytes": info.st_size,
            "allocated_bytes": getattr(info, "st_blocks", 0) * 512 if hasattr(info, "st_blocks") else None,
            "modified_at": dt.datetime.fromtimestamp(info.st_mtime, dt.timezone.utc).isoformat(),
            "last_used": "unknown; timestamps do not establish actual use",
            "metadata_fingerprint": hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
            "fingerprint_scope": "metadata only; not a content hash or race-free identity",
            "cleanup_eligibility": "UNASSESSED"}


def directory_metadata(path: Path, limit: int = 200) -> dict[str, Any]:
    if private_path(str(path)):
        return record("directory", "NOT RUN", path=display(str(path)), reason="private_path_excluded")
    try:
        rows, excluded, examined = [], 0, 0
        if os.name == "nt":
            return record("directory", "NOT RUN", reason="descriptor_directory_listing_unavailable")
        deadline = time.monotonic() + 5
        with exact_parent(path) as (parent, exact):
            descriptor = os.open(exact.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if examined >= limit or time.monotonic() > deadline:
                        return record("directory", "PARTIAL", path=display(str(path)), entries=rows,
                                      excluded=excluded, reason="entry_or_time_limit")
                    examined += 1
                    full = path / entry.name
                    if private_path(str(full)):
                        excluded += 1
                        continue
                    try:
                        rows.append(metadata(full, entry.stat(follow_symlinks=False)))
                    except OSError:
                        rows.append({"name": display(entry.name), "status": "NOT RUN", "reason": "metadata_unavailable"})
        finally:
            os.close(descriptor)
        incomplete = excluded or any(row.get("status") == "NOT RUN" for row in rows)
        return record("directory", "PARTIAL" if incomplete else "PASS", path=display(str(path)), entries=rows, excluded=excluded,
                      meaning="entry metadata only; excluded names are visibility gaps, contents/configuration not inspected")
    except (OSError, ValueError) as exc:
        return record("directory", "NOT RUN", path=display(str(path)), reason=type(exc).__name__)


def collect_macos() -> dict[str, Any]:
    import pwd  # Unix-only; this function is dispatched only on macOS.
    real_user, effective_user = pwd.getpwuid(os.getuid()), pwd.getpwuid(os.geteuid())
    home = Path(real_user.pw_dir)
    disk = shutil.disk_usage(home)
    commands = [
        ("os_version", ["/usr/bin/sw_vers", "-productVersion"]),
        ("os_build", ["/usr/bin/sw_vers", "-buildVersion"]),
        ("sip", ["/usr/bin/csrutil", "status"]),
        ("gatekeeper", ["/usr/sbin/spctl", "--status"]),
        ("filevault", ["/usr/bin/fdesetup", "status"]),
        ("firewall", ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]),
        ("memory_pressure", ["/usr/bin/memory_pressure", "-Q"]),
    ]
    checks = [native(name, argv) for name, argv in commands]
    firewall_state = next(row for row in checks if row["check"] == "firewall")
    checks.extend(native_preference(name, firewall_state) if os.getuid() == os.geteuid() and os.geteuid() != 0
                  else record(name, "NOT RUN", reason="user_scope_uncertain_under_elevation")
                  for name in NIST_PREFERENCES)
    checks.append(record("storage", "PASS", total_bytes=disk.total, free_bytes=disk.free,
                         used_bytes=disk.used, meaning="filesystem capacity, not a cleanup recommendation"))
    # No process arguments, environment, open files or network destination dumps.
    checks.append(native("processes", ["/bin/ps", "-axo", "pid=,ppid=,uid=,%cpu=,%mem=,comm="]))
    for directory in [home / "Library/LaunchAgents", Path("/Library/LaunchAgents"),
                      Path("/Library/LaunchDaemons")]:
        checks.append(directory_metadata(directory) if os.getuid() == os.geteuid() and os.geteuid() != 0 else
                      record("directory", "NOT RUN", path=display(str(directory)), reason="user_scope_uncertain_under_elevation"))
    for relative in [".agents/hooks", ".agents/skills", ".codex/skills", ".claude/skills",
                     ".claude/plugins", ".pi/agent/extensions", ".config/opencode/plugins"]:
        checks.append(directory_metadata(home / relative) if os.getuid() == os.geteuid() and os.geteuid() != 0 else
                      record("directory", "NOT RUN", path=display(str(home / relative)), reason="user_scope_uncertain_under_elevation"))
    for check in ["patch_freshness", "xprotect_runtime", "tcc_permissions", "configuration_profiles",
                  "browser_extensions", "account_security", "backup_restore", "network_connections",
                  "effective_harness_permissions", "package_advisories", "login_items", "privileged_helpers",
                  "system_network_extensions", "cron_periodic_jobs", "shell_startup", "ide_extensions"]:
        checks.append(record(check, "NOT RUN", reason="requires separate scoped native or manual verification"))
    summary = collection_summary(checks)
    return {"schema_version": 1, "collector_version": COLLECTOR_VERSION, "observed_at": now(), "platform": "macos",
            "architecture": platform.machine(), "scope": "bounded metadata baseline",
            "identity": {"real_uid": os.getuid(), "effective_uid": os.geteuid(),
                         "elevated": os.geteuid() == 0, "home_source": "OS account database; not HOME environment",
                         "home_matches_environment": os.environ.get("HOME") == real_user.pw_dir,
                         "effective_account_matches": real_user.pw_uid == effective_user.pw_uid,
                         "interpreter": display(sys.executable), "host_attestation": "NOT ATTESTED"},
            **summary, "verdict": "NOT ASSESSED", "checks": checks}


def collection_summary(checks: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {s: sum(c.get("status") == s for c in checks) for s in ("PASS", "FAIL", "PARTIAL", "NOT RUN")}
    return {"status": "FAIL" if counts["FAIL"] else "PARTIAL" if counts["PARTIAL"] or counts["NOT RUN"] else "PASS",
            "summary": counts, "status_scope": "individual checks and coverage, never host safety"}


def absolute_target(target: str, os_name: str) -> bool:
    if not plain_text(target):
        return False
    if any(c in target for c in "*?[]") or any(p in (".", "..") for p in re.split(r"[\\/]", target)):
        return False
    if target.startswith("process:"):
        return False  # A process name is not PID/start-time/executable identity.
    if target.startswith(("service:", "setting:", "account:", "package:")):
        kind, identifier = target.split(":", 1)
        if len(identifier) > 256 or identifier.casefold() in {"all", "any", "everything", "all-services", "all-processes"}:
            return False
        if kind == "package" and re.fullmatch(r"@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", identifier):
            return True
        return re.fullmatch(r"[A-Za-z0-9_@][A-Za-z0-9_.@+-]*(?::[A-Za-z0-9_.@+-]+)*", identifier) is not None and not re.match(r"^[A-Za-z]:", identifier)
    if os_name == "windows":
        tail = target[2:] if target.startswith(("\\\\", "//")) else target
        components = re.split(r"[\\/]", tail)
        ambiguous = any(p.endswith((".", " ")) or re.search(r"~[0-9]+", p)
                        or re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p)
                        for p in components if p)
        # No ADS, admin-share aliases, device paths or extra colons after a drive.
        rest = target[2:] if re.match(r"^[A-Za-z]:", target) else target
        if ":" in rest or any(p.endswith("$") for p in components):
            return False
        return PureWindowsPath(target).is_absolute() and not re.search(r"[\\/]{2}", tail) and not ambiguous
    return PurePosixPath(target).is_absolute() and "//" not in target and "\\" not in target


def unsafe_cleanup_target(target: str, os_name: str) -> bool:
    """Conservative lexical guards; no filesystem discovery or consent implied."""
    p = PureWindowsPath(target) if os_name == "windows" else PurePosixPath(target)
    if not p.is_absolute():
        return True
    parts = [x.casefold() for x in p.parts]
    if len(parts) < 3 or ".git" in parts:
        return True
    if any(part.endswith((".app", ".sparsebundle", ".backupbundle")) or
           part in {"backups.backupdb", ".timemachine", "windowsimagebackup"} for part in parts):
        return True
    if any(part in {"profiles", "chrome", "safari", "firefox", "brave-browser", "edge", "user data",
                    "microsoft edge", "chromium", "vivaldi", "google chrome canary", "default",
                    "mobile documents", "mail", "messages"} or re.fullmatch(r"profile [0-9]+", part) for part in parts):
        return True
    if os_name == "windows":
        if len(parts) <= 2 or parts[1] in {"windows", "program files", "program files (x86)", "programdata", "system volume information"}:
            return True
    else:
        if parts[1] in {"system", "usr", "bin", "sbin", "etc", "var", "opt", "applications"}:
            return True
        if parts[1] == "volumes":
            return True  # Mount aliases and backups need a separately verified native procedure.
        if len(parts) <= 2 or parts[1:3] in [["private", "etc"], ["private", "var"]]:
            return True
    for index, name in enumerate(parts):
        # Cross-platform home convention, without assuming the current user.
        if name in {"users", "home"} and len(parts) >= index + 2:
            home_length = index + 2
            if len(parts) <= home_length + 1:
                return True
            if parts[home_length] in {"documents", "desktop", "pictures", "movies", "music", "videos"} or parts[home_length].startswith("onedrive"):
                return True
        if name in {".codex", ".claude", ".pi", ".config", ".agents"} and index == len(parts) - 1:
            return True
        if name == "appdata" and len(parts) <= index + 3:
            return True
        if name in {"application support", "containers", "group containers"} and len(parts) <= index + 2:
            return True
        if name in {"caches", "preferences", "logs"} and index == len(parts) - 1:
            return True
    return False


def targets_overlap(first: str, second: str) -> bool:
    # Conservatively fold macOS too: case-sensitive volumes may get an extra
    # exclusion, but case-insensitive volumes must not lose one.
    def lexical(value: str) -> str:
        value = unicodedata.normalize("NFC", value).replace("\\", "/").rstrip("/").casefold()
        for prefix in ("/private/tmp", "/private/var", "/private/etc"):
            if value == prefix or value.startswith(prefix + "/"):
                value = value[len("/private"):]
        if value.startswith("/system/volumes/data/"):
            value = value[len("/system/volumes/data"):]
        return value
    a, b = lexical(first), lexical(second)
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def validate_plan(plan: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(plan, dict) or set(plan) != PLAN_KEYS:
        return ["Plan must contain exactly the documented fields; embedded approval is not supported"]
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        errors.append("schema_version must be 1")
    if not isinstance(plan["audit_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", plan["audit_id"]):
        errors.append("Invalid audit_id")
    if type(plan["revision"]) is not int or plan["revision"] < 1:
        errors.append("revision must be a positive integer")
    if plan["platform"] not in ("macos", "windows"):
        errors.append("platform must be macos or windows")
    try:
        timestamp = dt.datetime.fromisoformat(plan["created_at"])
        if timestamp.tzinfo is None:
            raise ValueError("timezone required")
    except (TypeError, ValueError):
        errors.append("created_at must be an ISO timestamp with timezone")
    scope = plan["scope"]
    if not isinstance(scope, dict) or set(scope) != {"machine", "exclusions"}:
        errors.append("scope must identify machine and exclusions")
    elif not plain_text(scope["machine"], 80) or not isinstance(scope["exclusions"], list) or len(scope["exclusions"]) > 128 or not all(isinstance(x, str) for x in scope["exclusions"]):
        errors.append("Invalid scope values")
    elif any(not absolute_target(x, plan["platform"]) for x in scope["exclusions"]):
        errors.append("Exclusions must be exact absolute paths or native resource IDs")
    actions = plan["actions"]
    if errors:
        return errors
    if not isinstance(actions, list) or len(actions) > 64:
        return ["actions must contain 0..64 actions"]
    graph: dict[str, list[str]] = {}
    for index, action in enumerate(actions):
        label = f"actions[{index}]"
        if not isinstance(action, dict) or set(action) != ACTION_KEYS:
            errors.append(f"{label}: unknown or missing fields")
            continue
        aid = action["id"]
        if not isinstance(aid, str) or not re.fullmatch(r"P[0-9]{2,4}", aid) or aid in graph:
            errors.append(f"{label}: invalid or duplicate ID")
            continue
        if not isinstance(action["category"], str) or action["category"] not in {"security", "recovery", "agent", "performance", "cleanup"}:
            errors.append(f"{aid}: invalid category")
        for field in ["operation", "reason", "risk", "rollback"]:
            if not plain_text(action[field], 2048):
                errors.append(f"{aid}: {field} must be nonempty text")
        for field in ["targets", "evidence", "preconditions", "verification", "stop_if"]:
            if not isinstance(action[field], list) or not 1 <= len(action[field]) <= 32 or not all(plain_text(v) for v in action[field]):
                errors.append(f"{aid}: {field} must be a nonempty text list")
        if errors:
            return errors  # Bound work before iterating attacker-controlled lists.
        if isinstance(action["targets"], list):
            for target in action["targets"]:
                if not isinstance(target, str) or not absolute_target(target, plan["platform"]):
                    errors.append(f"{aid}: target must be exact, absolute or a native resource ID")
                elif private_path(target):
                    errors.append(f"{aid}: protected credential/session target")
                elif not target.startswith(("service:", "setting:", "account:", "package:")) and unsafe_cleanup_target(target, plan["platform"]):
                    errors.append(f"{aid}: unsafe cleanup target; filesystem guard applies in every category")
                elif action["category"] == "cleanup" and ":" in target and not PureWindowsPath(target).is_absolute():
                    errors.append(f"{aid}: cleanup requires an exact filesystem target")
                if isinstance(target, str) and isinstance(scope, dict) and isinstance(scope.get("exclusions"), list):
                    for exclusion in scope["exclusions"]:
                        if isinstance(exclusion, str) and exclusion:
                            if targets_overlap(target, exclusion):
                                errors.append(f"{aid}: target overlaps a scope exclusion")
                                break
        dependencies = action["depends_on"]
        if not isinstance(dependencies, list) or len(dependencies) > 32 or not all(isinstance(v, str) and re.fullmatch(r"P[0-9]{2,4}", v) for v in dependencies):
            errors.append(f"{aid}: depends_on must be a text list")
            dependencies = []
        graph[aid] = dependencies
    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(aid: str) -> None:
        if aid in visiting:
            errors.append("Action dependencies contain a cycle")
            return
        if aid in visited:
            return
        visiting.add(aid)
        for dep in graph[aid]:
            if dep not in graph:
                errors.append(f"{aid}: unknown dependency {dep}")
            else:
                walk(dep)
        visiting.remove(aid)
        visited.add(aid)

    for aid in graph:
        walk(aid)
    return errors


def assess_emergency(case: Any, current: dt.datetime | None = None) -> dict[str, Any]:
    """Check a case record, never decide factual guilt, consent, or execution."""
    current = current or dt.datetime.now(dt.timezone.utc)
    errors: list[str] = []
    keys = {"authority_reference", "machine_id", "action", "platform", "target", "active_harm", "corroboration", "safeguards"}
    if not isinstance(case, dict) or set(case) != keys:
        return {"status": "FAIL", "eligible": False, "errors": ["Missing or unknown case fields"]}

    def fresh(value: Any) -> bool:
        try:
            stamp = dt.datetime.fromisoformat(value)
            return stamp.tzinfo is not None and 0 <= (current - stamp).total_seconds() <= 120
        except (TypeError, ValueError):
            return False

    machine_id = case["machine_id"]
    if not isinstance(machine_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", machine_id):
        errors.append("Missing verified machine label")
    authority = case["authority_reference"]
    authority_keys = {"source", "reference", "quote", "machine_id", "actions", "expires_at"}
    if not isinstance(authority, dict) or set(authority) != authority_keys:
        errors.append("Missing structured reference to real human authority")
    else:
        if authority["source"] not in {"current_human_request", "human_issued_policy"} or not plain_text(authority["reference"], 512) or not plain_text(authority["quote"], 4096):
            errors.append("Authority must quote a current human request or a verified human-issued policy")
        if authority["machine_id"] != machine_id or not isinstance(authority["actions"], list) or not 1 <= len(authority["actions"]) <= 4 or case["action"] not in authority["actions"]:
            errors.append("Authority does not cover this machine and action")
        expiry = authority["expires_at"]
        if expiry is not None or authority["source"] == "human_issued_policy":
            try:
                expiry_time = dt.datetime.fromisoformat(expiry)
                if expiry_time.tzinfo is None or expiry_time <= current:
                    raise ValueError("expired")
            except (TypeError, ValueError):
                errors.append("Policy expiry must be explicit, timezone-aware and still valid")
    if case["platform"] not in ("macos", "windows"):
        errors.append("Unsupported platform")
    if case["action"] not in ("suspend_process", "terminate_process", "isolate_process_network", "isolate_host"):
        errors.append("Unsupported containment action")
    target = case["target"]
    host_action = case["action"] == "isolate_host"
    if host_action:
        if (not isinstance(target, dict) or set(target) != {"machine_id", "owner_verified", "observed_at"}
                or target.get("machine_id") != machine_id or target.get("owner_verified") is not True
                or not fresh(target.get("observed_at"))):
            errors.append("Incomplete fresh host identity; do not invent a PID for host isolation")
    elif not isinstance(target, dict) or set(target) != {"pid", "start_time", "path", "owner_verified", "observed_at"}:
        errors.append("Incomplete target identity")
    else:
        if type(target["pid"]) is not int or target["pid"] <= (4 if case["platform"] == "windows" else 1):
            errors.append("Invalid or critical PID")
        try:
            started = dt.datetime.fromisoformat(target["start_time"])
            if started.tzinfo is None or started > current:
                raise ValueError("invalid start")
        except (TypeError, ValueError):
            errors.append("Target start time must be a verified ISO timestamp with timezone")
        executable = target["path"]
        absolute = (PureWindowsPath(executable).is_absolute() if case["platform"] == "windows" else PurePosixPath(executable).is_absolute()) if isinstance(executable, str) else False
        if not absolute or not absolute_target(executable, case["platform"]):
            errors.append("Missing exact executable path")
        elif ((case["platform"] == "windows" and
                (PureWindowsPath(executable).name.casefold() in {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe"}
                 or PureWindowsPath(executable).name.casefold() in {"msmpeng.exe", "mssense.exe", "nissrv.exe", "senseir.exe", "securityhealthservice.exe", "csfalconservice.exe", "sentinelagent.exe", "sentinelservicehost.exe", "cb.exe", "cylancesvc.exe"}
                 or any(p.casefold() == "windows" for p in PureWindowsPath(executable).parts)))
              or (case["platform"] == "macos" and
                  (executable.casefold().startswith(("/system/", "/sbin/", "/usr/libexec/", "/usr/sbin/"))
                   or PurePosixPath(executable).name.casefold() in {"launchd", "kernel_task", "windowserver", "loginwindow", "wdavdaemon", "falcond", "sentineld"}))):
            errors.append("Critical or system executable is outside this automatic containment gate")
        if target["owner_verified"] is not True or not fresh(target["observed_at"]):
            errors.append("Owner unverified or target observation stale")
    harm = case["active_harm"]
    if not isinstance(harm, dict) or set(harm) != {"kind", "evidence", "observed_at"}:
        errors.append("Incomplete active harm evidence")
    elif harm["kind"] not in ("unauthorized_destruction", "confirmed_exfiltration", "malicious_remote_control") or not isinstance(harm["evidence"], str) or not harm["evidence"].strip() or not fresh(harm["observed_at"]):
        errors.append("Active harm unproven or stale; symptoms/CVEs alone are insufficient")
    elif not host_action and isinstance(target, dict):
        try:
            if dt.datetime.fromisoformat(target["start_time"]) > dt.datetime.fromisoformat(harm["observed_at"]):
                errors.append("Process started after the alleged harm; identity mismatch")
        except (KeyError, TypeError, ValueError):
            errors.append("Process/harm chronology cannot be verified")
    sources = case["corroboration"]
    families: set[str] = set()
    if isinstance(sources, list) and len(sources) <= 8:
        for source in sources:
            identity_key = "target_machine_id" if host_action else "target_pid"
            source_keys = {"family", "source_id", identity_key, "evidence", "observed_at"}
            if not host_action:
                source_keys.add("target_start_time")
            if isinstance(source, dict) and set(source) == source_keys:
                family = source["family"]
                known_families = {"endpoint-engine", "filesystem-observation", "network-observation", "remote-control-observation"}
                matches = (source[identity_key] == machine_id if host_action else
                           isinstance(target, dict) and type(source[identity_key]) is int and source[identity_key] == target.get("pid")
                           and isinstance(source.get("target_start_time"), str)
                           and source.get("target_start_time") == target.get("start_time"))
                if matches and not host_action:
                    try:
                        matches = dt.datetime.fromisoformat(target["start_time"]) <= dt.datetime.fromisoformat(source["observed_at"])
                    except (KeyError, TypeError, ValueError):
                        matches = False
                if isinstance(family, str) and family in known_families and plain_text(source["source_id"], 256) and matches and plain_text(source["evidence"], 2048) and fresh(source["observed_at"]):
                    families.add(family)
        source_ids = [s.get("source_id") for s in sources if isinstance(s, dict) and isinstance(s.get("source_id"), str)]
        if len(source_ids) != len(set(source_ids)):
            errors.append("Duplicate source IDs are not independent evidence")
    if len(families) < 2:
        errors.append("Need two fresh independent evidence families tied to the target")
    guards = case["safeguards"]
    guard_keys = {"critical_processes_excluded", "agent_and_ancestors_excluded", "shared_work_checked", "control_channel_impact_checked"}
    if not isinstance(guards, dict) or set(guards) != guard_keys or any(v is not True for v in guards.values()):
        errors.append("Missing critical-process, active-work or control-channel safeguards")
    return {"status": "FAIL" if errors else "PASS", "eligible": not errors, "errors": errors,
            "meaning": "Record completeness only; independently verify truth, target and human authority",
            "execution": "NONE; a skill/tool record never grants permission"}


def digest_plan(plan: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def action_digests(plan: dict[str, Any]) -> dict[str, str]:
    """Bind each action to audit, platform and scope; never to embedded consent."""
    context = {key: plan[key] for key in ("audit_id", "platform", "scope")}
    return {action["id"]: digest_plan({**context, "action": action}) for action in plan["actions"]}


def inventory(root: Path, max_entries: int = 2000, max_depth: int = 4) -> dict[str, Any]:
    if not root.is_absolute() or ".." in root.parts or private_path(str(root)):
        raise ValueError("Use an exact absolute non-sensitive directory")
    # Broad user roots are not candidate directories. No implicit home scan.
    key = str(root).casefold().rstrip("/")
    home_key = str(Path.home()).casefold()
    if (root == Path(root.anchor) or key in {home_key, str(Path.home().parent).casefold(),
            "/users", "/home", "/system", "/library", "/applications", "/volumes"}
            or re.fullmatch(r"/(?:system/volumes/data/)?(?:users|home)/[^/]+", key)):
        raise ValueError("Choose a bounded candidate directory, not a broad root")
    if os.name == "nt":
        return {"status": "NOT RUN", "reason": "Use native Windows metadata inventory; safe descriptor walk unavailable"}
    if type(max_entries) is not int or not 1 <= max_entries <= 10000 or type(max_depth) is not int or not 0 <= max_depth <= 8:
        raise ValueError("Invalid inventory bounds")
    rows: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    excluded = 0
    examined = 0
    deadline = time.monotonic() + 5
    with exact_parent(root) as (parent, exact):
        descriptor = os.open(exact.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    root_device = os.fstat(descriptor).st_dev

    def walk(directory: Path, fd: int, depth: int) -> None:
        nonlocal examined, excluded
        with os.scandir(fd) as entries:
            for entry in entries:
                if examined >= max_entries or time.monotonic() >= deadline:
                    if not any(g["reason"] == "entry_or_time_limit" for g in gaps):
                        gaps.append({"path": display(str(directory)), "reason": "entry_or_time_limit"})
                    return
                examined += 1
                path = directory / entry.name
                if private_path(str(path)):
                    excluded += 1
                    continue
                child = None
                try:
                    info = entry.stat(follow_symlinks=False)
                    row = metadata(path, info)
                    rows.append(row)
                    if row["kind"] == "directory":
                        if info.st_dev != root_device or depth >= max_depth:
                            gaps.append({"path": row["path"], "reason": "depth_or_filesystem_boundary"})
                            continue
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        opened = os.fstat(child)
                        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                            raise ValueError("directory_identity_changed")
                        walk(path, child, depth + 1)
                except (OSError, ValueError) as exc:
                    gaps.append({"path": display(str(path)), "reason": type(exc).__name__})
                finally:
                    if child is not None:
                        os.close(child)
    try:
        walk(root, descriptor, 0)
    finally:
        os.close(descriptor)
    return {"status": "PARTIAL" if gaps or excluded else "PASS", "root": display(str(root)), "entries": rows,
            "gaps": gaps, "excluded": excluded, "cleanup_eligibility": "UNASSESSED",
            "meaning": "metadata only; no file contents read, no cleanup authorized"}


@contextmanager
def exact_parent(path: Path):
    """Anchor each POSIX parent descriptor, refusing symlinks rather than resolving them."""
    path = path.absolute()
    if private_path(str(path)) or any(c in str(path) for c in "*?[]") or ".." in path.parts:
        raise ValueError("Exact non-sensitive path required")
    if os.name == "nt" and not absolute_target(str(path), "windows"):
        raise ValueError("Ambiguous Windows JSON path rejected before opening")
    if os.name != "posix":
        for parent in [path, *path.parents]:
            if parent.is_symlink() or (parent.exists() and bool(getattr(parent.lstat(), "st_file_attributes", 0)
                                                               & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))):
                raise ValueError("Reparse/symlink path rejected")
        yield None, path
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor, path
    finally:
        os.close(descriptor)


def verify_regular_descriptor(descriptor: int, expected: Path) -> os.stat_result:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Only a single-link regular file is accepted")
    if os.name == "nt":
        # Check the actual opened Windows handle before reading/writing bytes.
        # Native execution is a separate release gate; no reparse safety inferred from mocks.
        import ctypes
        from ctypes import wintypes
        import msvcrt
        get_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
        get_path.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
        get_path.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_path(msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise OSError("Opened file identity unavailable")
        actual = buffer.value
        if actual.startswith("\\\\?\\UNC\\"):
            actual = "\\\\" + actual[8:]
        elif actual.startswith("\\\\?\\"):
            actual = actual[4:]
        if os.path.normcase(actual) != os.path.normcase(str(expected)):
            raise ValueError("Opened path differs from the exact requested path")
    return info


def read_plan(path: Path, max_bytes: int = 1_048_576) -> Any:
    if type(max_bytes) is not int or not 1 <= max_bytes <= 4_194_304:
        raise ValueError("Invalid JSON byte bound")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with exact_parent(path) as (parent, absolute):
        descriptor = os.open(absolute.name if parent is not None else absolute, flags, dir_fd=parent)
    with os.fdopen(descriptor, "rb") as handle:
        info = verify_regular_descriptor(handle.fileno(), absolute)
        if info.st_size > max_bytes:
            raise ValueError("Only bounded regular JSON files are accepted")
        content = handle.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise ValueError("Input grew beyond the limit")
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key")
            value[key] = item
        return value

    def reject_constant(value):
        raise ValueError("Non-finite JSON value")

    # json.loads(bytes) recognizes UTF BOMs, including Windows PowerShell 5.1
    # redirection's UTF-16. The same byte bound and strict JSON hooks still apply.
    return json.loads(content, object_pairs_hook=unique_pairs,
                      parse_constant=reject_constant)


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("collect", help="macOS metadata baseline; never remediates")
    inv = commands.add_parser("inventory", help="Metadata only, no symlink traversal or file reads")
    inv.add_argument("--root", type=Path, required=True)
    inv.add_argument("--max-entries", type=int, default=2000, choices=range(1, 10001), metavar="1..10000")
    inv.add_argument("--max-depth", type=int, default=4, choices=range(0, 9), metavar="0..8")
    for name in ["validate-plan", "digest-plan", "assess-emergency"]:
        sub = commands.add_parser(name, help="Validate structure only; never consent or execution")
        sub.add_argument("plan", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            result = collect_macos() if sys.platform == "darwin" else {
                "status": "NOT RUN", "reason": "Use windows_collect.ps1 on Windows; macOS collector is OS-specific"}
        elif args.command == "inventory":
            result = inventory(args.root, args.max_entries, args.max_depth)
        else:
            plan = read_plan(args.plan)
            if args.command == "assess-emergency":
                result = assess_emergency(plan)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                return 0 if result["eligible"] else 1
            errors = validate_plan(plan)
            result = {"status": "FAIL" if errors else "PASS", "errors": errors,
                      "authorization": "NOT ASSESSED; human decision required"}
            if not errors:
                result["plan_sha256"] = digest_plan(plan)
                result["action_sha256"] = action_digests(plan)
                if args.command == "digest-plan":
                    result["canonical_plan"] = plan
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 1 if errors else 0
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1 if result.get("status") == "FAIL" else 2 if result.get("status") in {"NOT RUN", "PARTIAL"} else 0
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        print(json.dumps({"status": "FAIL", "error_type": type(exc).__name__,
                          "reason": "invalid or inaccessible input; no changes performed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
