"""Deterministic safety tests. All filesystem writes are disposable fixtures."""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/pc-security-audit/scripts/audit.py"
spec = importlib.util.spec_from_file_location("pc_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
STAMP = "2026-10-23T10:00:00+00:00"
CURRENT = dt.datetime.fromisoformat(STAMP)


def plan():
    return {"schema_version": 1, "audit_id": "test-01", "revision": 1, "platform": "macos",
            "created_at": STAMP, "scope": {"machine": "fixture", "exclusions": []},
            "actions": [{"id": "P01", "category": "cleanup", "targets": ["/example/cache/generated"],
                         "operation": "Trash exact generated cache", "reason": "Measured, regenerable",
                         "evidence": ["F01 metadata"], "preconditions": ["Owner app closed"],
                         "risk": "Regeneration latency", "rollback": "Restore from Trash",
                         "verification": ["App still works"], "stop_if": ["Target changed"],
                         "depends_on": []}]}


def emergency():
    return {"authority_reference": {"source": "current_human_request", "reference": "human-message-42",
                "quote": "Suspend the verified harmful process on fixture", "machine_id": "fixture",
                "actions": ["suspend_process"], "expires_at": None}, "machine_id": "fixture",
            "action": "suspend_process", "platform": "macos",
            "target": {"pid": 4567, "start_time": "2026-10-23T09:00:00+00:00", "path": "/example/tool/app",
                       "owner_verified": True, "observed_at": STAMP},
            "active_harm": {"kind": "unauthorized_destruction", "evidence": "Fixture behavior event F01", "observed_at": STAMP},
            "corroboration": [{"family": "endpoint-engine", "source_id": "edr-event-01", "target_pid": 4567, "target_start_time": "2026-10-23T09:00:00+00:00", "evidence": "F01", "observed_at": STAMP},
                              {"family": "filesystem-observation", "source_id": "fs-event-02", "target_pid": 4567, "target_start_time": "2026-10-23T09:00:00+00:00", "evidence": "F02", "observed_at": STAMP}],
            "safeguards": {"critical_processes_excluded": True, "agent_and_ancestors_excluded": True,
                           "shared_work_checked": True, "control_channel_impact_checked": True}}


class PlanTests(unittest.TestCase):
    def test_native_ids_cannot_disguise_filesystem_targets(self):
        for category in ("security", "agent", "recovery", "performance", "cleanup"):
            for target in ("setting:/Users/fixture/Documents/thesis", "package:/", "service:../../tmp", r"setting:C:\Windows"):
                value=plan(); value["actions"][0].update(category=category,targets=[target])
                self.assertTrue(audit.validate_plan(value), (category,target))
        value=plan(); value["actions"][0].update(category="security",targets=["package:@scope/name"])
        self.assertEqual([],audit.validate_plan(value))

    def test_cli_json_is_utf8_even_if_caller_configured_ascii_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory).resolve()/"plan.json"
            value=plan(); value["actions"][0]["reason"]="Neve \u2744 verificata"
            path.write_text(json.dumps(value),encoding="utf-8")
            code="import sys,runpy; sys.stdout.reconfigure(encoding='ascii'); sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"
            result=subprocess.run([sys.executable,"-I","-S","-B","-c",code,str(SCRIPT),"digest-plan",str(path)],capture_output=True,timeout=10)
            self.assertEqual(0,result.returncode)
            self.assertEqual(value,json.loads(result.stdout)["canonical_plan"])

    def test_action_digest_retains_unchanged_authority_but_binds_scope(self):
        old=plan(); new=copy.deepcopy(old)
        extra=copy.deepcopy(new["actions"][0]); extra["id"]="P02"
        new["actions"].append(extra); new["revision"]=2
        self.assertEqual(audit.action_digests(old)["P01"],audit.action_digests(new)["P01"])
        new["scope"]["machine"]="other"
        self.assertNotEqual(audit.action_digests(old)["P01"],audit.action_digests(new)["P01"])

    def test_filesystem_guards_cannot_be_bypassed_by_category(self):
        for category in ("cleanup", "security", "performance", "agent", "recovery"):
            for target in ("/", "/Users/fixture", "/Applications/Test.app", "/Volumes/Backup", "/opt/homebrew",
                           "/Users/fixture/Documents/thesis", "/example/file\u202e.txt", "/example/Cafe\u0301"):
                value = plan()
                value["actions"][0].update(category=category, targets=[target])
                self.assertTrue(audit.validate_plan(value), (category, target))

    def test_windows_ads_devices_admin_shares_and_name_only_processes_rejected(self):
        value = plan()
        value["platform"] = "windows"
        for target in (r"C:\tmp\item:stream", r"C:\tmp\NUL.txt", r"C:\tmp\COM1", r"\\localhost\C$\tmp\item", "process:node"):
            value["actions"][0]["targets"] = [target]
            self.assertTrue(audit.validate_plan(value), target)

    def test_bounded_plan_lists_and_visible_canonical_text(self):
        for field in ("targets", "evidence", "preconditions", "verification", "stop_if"):
            value = plan()
            value["actions"][0][field] *= 33
            self.assertTrue(audit.validate_plan(value))
        value = plan()
        value["scope"]["exclusions"] = ["/example/cache/keep"] * 129
        self.assertTrue(audit.validate_plan(value))
        value = plan()
        value["actions"][0]["operation"] += "\u200b"
        self.assertTrue(audit.validate_plan(value))

    def test_fixed_macos_aliases_do_not_escape_exclusions(self):
        self.assertTrue(audit.targets_overlap("/private/tmp/keep/item", "/tmp/keep"))
        self.assertTrue(audit.targets_overlap("/System/Volumes/Data/Users/fixture/keep/a", "/Users/fixture/keep"))

    def test_no_recommended_actions_is_valid_without_fabricating_work(self):
        value = plan()
        value["actions"] = []
        self.assertEqual([], audit.validate_plan(value))

    def test_complete_plan_and_order_independent_digest(self):
        value = plan()
        self.assertEqual([], audit.validate_plan(value))
        self.assertEqual(audit.digest_plan(value), audit.digest_plan(dict(reversed(list(value.items())))))

    def test_approval_cannot_be_smuggled_into_plan(self):
        value = plan()
        value["approved"] = True
        self.assertTrue(audit.validate_plan(value))

    def test_action_change_invalidates_digest(self):
        before = plan()
        after = copy.deepcopy(before)
        after["actions"][0]["targets"] = ["/example/cache/other"]
        self.assertNotEqual(audit.digest_plan(before), audit.digest_plan(after))

    def test_missing_rollback_and_unbounded_targets_rejected(self):
        for target in ["/", "~/.cache/*", "/example/.env.local", "/example/sessions/current", "/example/../cache", "service:all"]:
            with self.subTest(target=target):
                value = plan()
                value["actions"][0]["targets"] = [target]
                self.assertTrue(audit.validate_plan(value))
        value = plan()
        value["actions"][0]["rollback"] = ""
        self.assertTrue(audit.validate_plan(value))

    def test_native_resource_allowed_for_non_cleanup(self):
        value = plan()
        value["actions"][0]["category"] = "security"
        value["actions"][0]["targets"] = ["setting:firewall:public"]
        self.assertEqual([], audit.validate_plan(value))

    def test_windows_exact_path_and_drive_root(self):
        value = plan()
        value["platform"] = "windows"
        value["actions"][0]["targets"] = ["C:\\Users\\Fixture\\AppData\\Local\\Vendor\\Cache\\item"]
        self.assertEqual([], audit.validate_plan(value))
        value["actions"][0]["targets"] = ["C:\\"]
        self.assertTrue(audit.validate_plan(value))

    def test_cycles_unknown_dependencies_and_duplicate_ids(self):
        value = plan()
        value["actions"][0]["depends_on"] = ["P01"]
        self.assertTrue(audit.validate_plan(value))
        value["actions"][0]["depends_on"] = ["P02"]
        self.assertTrue(audit.validate_plan(value))
        value["actions"].append(copy.deepcopy(value["actions"][0]))
        self.assertTrue(audit.validate_plan(value))

    def test_invalid_types_and_time(self):
        value = plan()
        value["revision"] = True
        value["created_at"] = "2026-10-23T10:00:00"
        value["actions"][0]["category"] = []
        self.assertTrue(audit.validate_plan(value))

    def test_exclusion_ancestors_case_aliases_and_invalid_paths(self):
        for target in ["/example/cache", "/example/cache/keep/item", "/EXAMPLE/CACHE/KEEP/item"]:
            value = plan()
            value["scope"]["exclusions"] = ["/example/cache/keep"]
            value["actions"][0]["targets"] = [target]
            self.assertTrue(audit.validate_plan(value))
        for target in ["/example/./cache/item", "/example//cache/item"]:
            value = plan()
            value["actions"][0]["targets"] = [target]
            self.assertTrue(audit.validate_plan(value))
        value = plan()
        value["scope"]["exclusions"] = ["relative-backups"]
        self.assertTrue(audit.validate_plan(value))

    def test_cleanup_cannot_target_home_system_or_auth_container(self):
        for target in ["/Users/fixture", "/Users/fixture/Library", "/usr/bin", "/System/Library",
                       "/Users/fixture/.codex", "/Users/fixture/.claude",
                       "/Users/fixture/Library/Application Support/Google/Chrome/Default"]:
            value = plan()
            value["actions"][0]["targets"] = [target]
            self.assertTrue(audit.validate_plan(value), target)
        value = plan()
        value["platform"] = "windows"
        value["actions"][0]["targets"] = ["C:\\Users\\Fixture"]
        self.assertTrue(audit.validate_plan(value))

    def test_credentials_histories_and_journals_are_excluded(self):
        for name in ["id_ed25519", ".git-credentials", ".zsh_history", "Login Data-journal", "Cookies-wal", "Local State", "history.jsonl"]:
            value = plan()
            value["actions"][0]["targets"] = ["/example/cache/" + name]
            self.assertTrue(audit.validate_plan(value), name)

    def test_browser_history_and_dpapi_are_not_action_targets(self):
        cases = [("macos", "/Users/fixture/Library/Safari/History.db"),
                 ("macos", "/example/browser/places.sqlite"),
                 ("windows", "C:\\Users\\Fixture\\AppData\\Roaming\\Microsoft\\Protect"),
                 ("windows", "C:\\Users\\Fixture\\AppData\\Local\\Microsoft\\Vault")]
        for os_name, target in cases:
            value = plan()
            value["platform"] = os_name
            value["actions"][0]["category"] = "security"
            value["actions"][0]["targets"] = [target]
            self.assertTrue(any("protected credential/session target" in x for x in audit.validate_plan(value)), target)

    def test_shared_parent_containers_and_system_alias_rejected(self):
        for target in ["/var/db/x/y", "/private/var/db/x/y", "/Users/fixture/Library/Application Support",
                       "/example/work/.codex"]:
            value = plan()
            value["actions"][0]["targets"] = [target]
            self.assertTrue(any("unsafe cleanup target" in x for x in audit.validate_plan(value)), target)
        value = plan()
        value["platform"] = "windows"
        value["actions"][0]["targets"] = ["C:\\Users\\Fixture\\AppData\\Local"]
        self.assertTrue(any("unsafe cleanup target" in x for x in audit.validate_plan(value)))

    def test_win32_alias_forms_and_broad_native_ids_rejected(self):
        for target in ["C:\\Users\\Fixture\\Backups.\\old", "C:\\Users\\Fixture\\Backups \\old", "C:\\Users\\Fixture\\BACKUP~1\\old"]:
            value = plan()
            value["platform"] = "windows"
            value["actions"][0]["targets"] = [target]
            self.assertTrue(any("target must be exact" in x for x in audit.validate_plan(value)), target)
        for category in ["security", "agent", "cleanup"]:
            value = plan()
            value["actions"][0]["category"] = category
            value["actions"][0]["targets"] = ["service:all"]
            self.assertTrue(any("target must be exact" in x for x in audit.validate_plan(value)))


@unittest.skipUnless(os.name == "posix", "macOS/POSIX metadata and native-state fixtures")
class MetadataTests(unittest.TestCase):
    def test_inventory_opens_only_directory_descriptors_not_discovered_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "sample.txt").write_text("fixture-only-content")
            original = os.open
            def directory_only(path, flags, *args, **kwargs):
                self.assertTrue(flags & os.O_DIRECTORY, "Inventory tried to open a discovered regular file")
                return original(path, flags, *args, **kwargs)
            with patch.object(audit.os, "open", side_effect=directory_only), patch("builtins.open", side_effect=AssertionError("No file body reads")), patch.object(Path, "open", side_effect=AssertionError("No file body reads")):
                self.assertEqual("PASS", audit.inventory(root)["status"])
                self.assertEqual("PASS", audit.directory_metadata(root)["status"])

    def test_excluded_entries_are_partial_and_count_toward_the_work_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for i in range(8):
                (root / f"sessionstore-{i}").mkdir()
            value = audit.directory_metadata(root, limit=2)
            self.assertEqual("PARTIAL", value["status"])
            self.assertEqual(2, value["excluded"])
            self.assertEqual([], value["entries"])
            value = audit.inventory(root, max_entries=3)
            self.assertEqual("PARTIAL", value["status"])
            self.assertEqual(3, value["excluded"])

    def test_contradictory_native_protection_summary_is_not_pass(self):
        with patch.object(audit, "run_bounded", return_value=subprocess.CompletedProcess([], 0, b"Firewall is enabled. (State = 0)\n", b"")):
            self.assertEqual("PARTIAL", audit.native("firewall", [sys.executable])["status"])

    @unittest.skipUnless(hasattr(os, "fwalk"), "Descriptor-safe inventory is POSIX-only")
    def test_no_file_content_reads_or_secret_directory_traversal(self):
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace).resolve()
            (root / "cache").mkdir()
            (root / "cache/item").write_text("fixture")
            (root / ".env").write_text("sentinel-secret")
            (root / "sessions").mkdir()
            (root / "sessions/private").write_text("sentinel-secret")
            with patch.object(Path, "open", side_effect=AssertionError("file opened")):
                result = audit.inventory(root)
            names = {x["name"] for x in result["entries"]}
            self.assertEqual({"cache", "item"}, names)
            self.assertNotIn("sentinel-secret", json.dumps(result))
            self.assertEqual("UNASSESSED", result["cleanup_eligibility"])
            self.assertTrue((root / "cache/item").exists())

    @unittest.skipUnless(hasattr(os, "fwalk"), "POSIX")
    def test_symlinks_not_followed_and_symlinked_roots_rejected(self):
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace).resolve()
            target = root / "outside"
            target.mkdir()
            (target / "private").write_text("fixture")
            candidate = root / "candidate"
            candidate.mkdir()
            (candidate / "link").symlink_to(target, target_is_directory=True)
            result = audit.inventory(candidate)
            self.assertEqual(["symlink"], [row["kind"] for row in result["entries"]])
            with self.assertRaises((ValueError, OSError)):
                audit.inventory(candidate / "link")

    @unittest.skipUnless(hasattr(os, "fwalk"), "POSIX")
    def test_limits_and_metadata_changes(self):
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace).resolve()
            for i in range(3):
                (root / f"item{i}").write_text("a")
            result = audit.inventory(root, max_entries=1)
            self.assertEqual("PARTIAL", result["status"])
            self.assertEqual(1, len(result["entries"]))
            before = audit.metadata(root / "item0")["metadata_fingerprint"]
            (root / "item0").write_text("changed")
            self.assertNotEqual(before, audit.metadata(root / "item0")["metadata_fingerprint"])

    def test_broad_or_sensitive_root_rejected(self):
        for root in [Path("/"), Path.home(), Path("/tmp/.ssh")]:
            with self.subTest(root=root), self.assertRaises(ValueError):
                audit.inventory(root)

    def test_native_error_bodies_never_returned(self):
        error = subprocess.CompletedProcess(["fixture"], 1, b"secret stdout", b"secret stderr")
        with patch.object(Path, "is_file", return_value=True), patch.object(audit, "run_bounded", return_value=error):
            result = audit.native("fixture", ["/example/native"])
        self.assertEqual("NOT RUN", result["status"])
        self.assertNotIn("secret", json.dumps(result))

    def test_disabled_gatekeeper_is_a_finding_not_a_missing_check(self):
        result = subprocess.CompletedProcess(["spctl"], 1, b"assessments disabled\n", b"")
        with patch.object(Path, "is_file", return_value=True), patch.object(audit, "run_bounded", return_value=result):
            record = audit.native("gatekeeper", ["/usr/sbin/spctl", "--status"])
        self.assertEqual("FAIL", record["status"])
        self.assertFalse(record["enabled"])

    def test_disabled_protections_and_unknown_transition_do_not_pass(self):
        for name, output in [("sip", b"System Integrity Protection status: disabled."),
                             ("filevault", b"FileVault is Off."),
                             ("firewall", b"Firewall is disabled. (State = 0)")]:
            response = subprocess.CompletedProcess(["fixture"], 0, output, b"")
            with patch.object(Path, "is_file", return_value=True), patch.object(audit, "run_bounded", return_value=response):
                result = audit.native(name, ["/example/native"])
            self.assertEqual("PASS", result["collection_status"])
            self.assertEqual("FAIL", result["protection_status"])
            self.assertEqual("FAIL", result["status"])
        response = subprocess.CompletedProcess(["fixture"], 0, b"Encryption in progress", b"")
        with patch.object(Path, "is_file", return_value=True), patch.object(audit, "run_bounded", return_value=response):
            result = audit.native("filevault", ["/example/native"])
        self.assertEqual("PARTIAL", result["status"])

    def test_known_secret_patterns_redacted(self):
        self.assertNotIn("sentinel", audit.display("password=sentinel Bearer sentinel token=sentinel"))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX")
    def test_named_pipe_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as workspace:
            target = Path(workspace).resolve() / "plan.json"
            os.mkfifo(target)
            result = subprocess.run([sys.executable, str(SCRIPT), "validate-plan", str(target)],
                                    capture_output=True, text=True, timeout=2)
            self.assertEqual(1, result.returncode)
            self.assertEqual("FAIL", json.loads(result.stdout)["status"])


class EmergencyTests(unittest.TestCase):
    def test_missing_start_time_with_null_evidence_fails_as_structured_record(self):
        case=emergency(); del case["target"]["start_time"]
        for evidence in case["corroboration"]: evidence["target_start_time"]=None
        result=audit.assess_emergency(case,CURRENT)
        self.assertFalse(result["eligible"])
        self.assertEqual("FAIL",result["status"])

    def test_process_reuse_chronology_and_security_engines_are_excluded(self):
        case=emergency(); case["target"]["start_time"]="2026-10-23T09:59:30+00:00"
        self.assertFalse(audit.assess_emergency(case,CURRENT)["eligible"])
        case=emergency(); case["active_harm"]["observed_at"]="2026-10-23T08:59:00+00:00"
        self.assertFalse(audit.assess_emergency(case,CURRENT)["eligible"])
        for platform,path in (("macos","/system/Library/TrustedService"),
                              ("windows",r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe")):
            case=emergency(); case["platform"]=platform; case["target"]["path"]=path
            self.assertFalse(audit.assess_emergency(case,CURRENT)["eligible"])

    def test_authority_is_bound_to_machine_action_and_policy_expiry(self):
        for change in ({"machine_id": "other"}, {"actions": ["terminate_process"]},
                       {"source": "project_file"}, {"source": "human_issued_policy", "expires_at": None},
                       {"source": "human_issued_policy", "expires_at": "2026-10-22T10:00:00+00:00"}):
            case = emergency()
            case["authority_reference"].update(change)
            self.assertFalse(audit.assess_emergency(case, CURRENT)["eligible"])

    def test_critical_windows_pid_and_system_images_rejected(self):
        for pid, path in ((4, r"C:\example\app.exe"), (4567, r"C:\Windows\System32\lsass.exe"),
                          (4567, r"C:\other\csrss.exe")):
            case = emergency()
            case["platform"] = "windows"
            case["target"].update(pid=pid, path=path)
            for item in case["corroboration"]:
                item["target_pid"] = pid
            self.assertFalse(audit.assess_emergency(case, CURRENT)["eligible"])
        case = emergency()
        case["target"]["start_time"] = "verified"
        self.assertFalse(audit.assess_emergency(case, CURRENT)["eligible"])

    def test_host_isolation_uses_host_evidence_and_never_fabricates_a_pid(self):
        case = emergency()
        case["action"] = "isolate_host"
        case["authority_reference"]["actions"] = ["isolate_host"]
        case["target"] = {"machine_id": "fixture", "owner_verified": True, "observed_at": STAMP}
        for item in case["corroboration"]:
            del item["target_pid"]
            del item["target_start_time"]
            item["target_machine_id"] = "fixture"
        self.assertTrue(audit.assess_emergency(case, CURRENT)["eligible"])
        case["corroboration"][0]["target_machine_id"] = "other"
        self.assertFalse(audit.assess_emergency(case, CURRENT)["eligible"])

    def test_fresh_complete_record_does_not_authorize_or_execute(self):
        result = audit.assess_emergency(emergency(), CURRENT)
        self.assertTrue(result["eligible"])
        self.assertIn("never grants permission", result["execution"])

    def test_symptoms_not_active_harm(self):
        for symptom in ["high_cpu", "unsigned_binary", "vulnerability", "old_alert"]:
            value = emergency()
            value["active_harm"]["kind"] = symptom
            self.assertFalse(audit.assess_emergency(value, CURRENT)["eligible"])

    def test_duplicate_evidence_not_independent(self):
        value = emergency()
        value["corroboration"][1]["family"] = "endpoint-engine"
        self.assertFalse(audit.assess_emergency(value, CURRENT)["eligible"])

    def test_evidence_aliases_duplicate_source_and_other_pid_block(self):
        value = emergency()
        value["corroboration"][0]["family"] = "EDR"
        value["corroboration"][1]["family"] = "edr-screenshot"
        self.assertFalse(audit.assess_emergency(value, CURRENT)["eligible"])
        value = emergency()
        value["corroboration"][1]["source_id"] = value["corroboration"][0]["source_id"]
        self.assertFalse(audit.assess_emergency(value, CURRENT)["eligible"])
        value = emergency()
        value["corroboration"][1]["target_pid"] = 9999
        self.assertFalse(audit.assess_emergency(value, CURRENT)["eligible"])

    def test_missing_human_authority_or_safeguard_blocks(self):
        value = emergency()
        value["authority_reference"] = ""
        self.assertFalse(audit.assess_emergency(value, CURRENT)["eligible"])
        value = emergency()
        value["safeguards"]["agent_and_ancestors_excluded"] = False
        self.assertFalse(audit.assess_emergency(value, CURRENT)["eligible"])

    def test_stale_or_future_identity_blocks(self):
        for stamp in ["2026-10-23T09:00:00Z", "2026-10-23T11:00:00Z"]:
            value = emergency()
            value["target"]["observed_at"] = stamp
            self.assertFalse(audit.assess_emergency(value, CURRENT)["eligible"])

    def test_cli_has_no_mutation_command(self):
        with tempfile.TemporaryDirectory() as workspace:
            target = Path(workspace) / "preserve.txt"
            target.write_text("must survive")
            result = subprocess.run([sys.executable, str(SCRIPT), "delete", str(target)], capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertEqual("must survive", target.read_text())

    def test_plan_exclusions_are_enforced(self):
        value = plan()
        value["scope"]["exclusions"] = ["/example/cache"]
        self.assertTrue(audit.validate_plan(value))


if __name__ == "__main__":
    unittest.main()
