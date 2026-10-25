"""Safety properties of local observations; all files and subprocesses are fixtures."""
import copy
import datetime as dt
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/pc-security-audit/scripts"
sys.path.insert(0, str(SCRIPTS))
import audit
import periodic

NOW = dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc)


def collected(at=NOW, enabled=True):
    return {"schema_version": 1, "collector_version": "0.2.0", "platform": "macos",
            "architecture": "arm64", "observed_at": at.isoformat(), "checks": [
                {"check": "sip", "status": "PASS" if enabled else "FAIL", "observed_at": at.isoformat(),
                 "collection_status": "PASS", "protection_status": "PASS" if enabled else "FAIL", "enabled": enabled},
                {"check": "processes", "status": "PASS", "observed_at": at.isoformat(), "output": "Unstable PID CPU text"}]}


def snap(at=NOW, enabled=True):
    return periodic.make_snapshot(collected(at, enabled), "fixture-machine", "host", "scope-v1", current=at)


class PeriodicTests(unittest.TestCase):
    def test_identical_partial_concerns_do_not_generate_repeated_loss_notifications(self):
        after=NOW+dt.timedelta(hours=1)
        def value(at):
            raw=collected(at,enabled=False)
            raw["checks"][0].update(collection_status="PARTIAL",protection_status="NOT ASSESSED")
            return periodic.make_snapshot(raw,"fixture","host","scope",current=at)
        result=periodic.compare(value(NOW),value(after),clock=after)
        self.assertEqual([],result["coverage_lost"])
        self.assertEqual(["sip"],result["persistent_concerns"])
        self.assertFalse(result["notify"])

    def test_readability_recovery_does_not_report_a_visibility_regression(self):
        after=NOW+dt.timedelta(days=1)
        for name in ("sip","gatekeeper","filevault","firewall","secure_boot"):
            old,new=collected(),collected(after)
            old["checks"]=[{"check":name,"status":"NOT RUN","observed_at":NOW.isoformat()}]
            fields={"data":{"enabled":True}} if name=="secure_boot" else {"enabled":True}
            new["checks"]=[{"check":name,"status":"PASS","observed_at":after.isoformat(),**fields}]
            previous=periodic.make_snapshot(old,"fixture","host","scope",current=NOW)
            current=periodic.make_snapshot(new,"fixture","host","scope",current=after)
            self.assertEqual([],periodic.compare(previous,current,clock=after)["coverage_lost"],name)

    def test_contradictory_unrun_stale_protection_is_never_preserved_as_pass(self):
        value=collected()
        value["checks"][0].update(collection_status="NOT RUN",protection_status="PASS",observed_at=(NOW-dt.timedelta(days=90)).isoformat())
        result=periodic.make_snapshot(value,"fixture","host","scope",current=NOW)
        self.assertEqual("NOT RUN",result["checks"]["sip"]["collection_status"])
        self.assertEqual("NOT RUN",result["checks"]["sip"]["protection_status"])

    def test_error_codes_do_not_echo_untrusted_error_text_or_paths(self):
        self.assertEqual("collector_stale_or_future",periodic.error_code(ValueError("Collector is stale or from the future")))
        self.assertNotIn("sentinel-private",periodic.error_code(ValueError("password=sentinel-private")))
        self.assertEqual("output_exists_no_overwrite",periodic.error_code(FileExistsError("sentinel-private")))
        value=collected()
        value["checks"]=[{"check":"directory","status":"PASS","observed_at":NOW.isoformat(),
                          "entries":[],"excluded":"sentinel-private"}]
        with self.assertRaises(ValueError): periodic.make_snapshot(value,"fixture","host","scope",current=NOW)

    def test_partial_concern_cannot_improve_from_older_or_incomplete_evidence(self):
        after = NOW + dt.timedelta(hours=1)
        old = collected(enabled=False)
        old["checks"][0]["collection_status"] = "PARTIAL"
        old["checks"][0]["protection_status"] = "NOT ASSESSED"
        new = collected(after, enabled=True)
        new["checks"][0]["observed_at"] = (NOW-dt.timedelta(days=120)).isoformat()
        previous = periodic.make_snapshot(old, "fixture", "host", "scope", current=NOW)
        current = periodic.make_snapshot(new, "fixture", "host", "scope", current=after)
        result = periodic.compare(previous, current, clock=after)
        self.assertEqual([], result["observed_improvements"])
        self.assertIn("sip", result["unverified_prior_concerns"])

    def test_exclusion_counts_and_inbound_allow_changes_are_preserved(self):
        after = NOW+dt.timedelta(days=1)
        def value(at, count, inbound):
            raw=collected(at)
            raw["checks"]=[{"check":"defender_exclusion_counts","status":"PASS","observed_at":at.isoformat(),
                "data":{"path_count":count,"process_count":0,"extension_count":0}},
                {"check":"firewall","status":"PASS","observed_at":at.isoformat(),
                 "data":[{"Name":"Public","Enabled":"True","DefaultInboundAction":inbound}]}]
            return periodic.make_snapshot(raw,"fixture","host","scope",current=at)
        result=periodic.compare(value(NOW,0,"Block"),value(after,3,"Allow"),clock=after)
        self.assertIn("defender_exclusion_counts",result["changed"])
        self.assertIn("firewall",result["current_concerns"])

    def test_passive_or_unknown_defender_role_requires_independent_verification(self):
        for mode in ("Passive", "unknown"):
            value = collected()
            data = {key: True for key in ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled",
                    "BehaviorMonitorEnabled", "IoavProtectionEnabled", "IsTamperProtected")}
            data["AMRunningMode"] = mode
            value["checks"][0] = {"check": "defender", "status": "PASS", "protection_status": "PASS",
                "collection_status": "PASS", "data": data, "observed_at": NOW.isoformat()}
            result = periodic.make_snapshot(value, "fixture", "host", "scope", current=NOW)
            self.assertEqual("PARTIAL", result["checks"]["defender"]["status"])
            self.assertEqual("NOT ASSESSED", result["checks"]["defender"]["protection_status"])

    def test_os_build_and_windows_version_changes_are_not_discarded(self):
        after = NOW + dt.timedelta(days=1)
        for name, first, second in (("os_build", {"output": "25A341"}, {"output": "25B100"}),
                ("os_and_memory", {"data": {"Version": "10.0.1", "BuildNumber": "100"}},
                                    {"data": {"Version": "10.0.2", "BuildNumber": "101"}})):
            old, new = collected(), collected(after)
            for value, fields in ((old, first), (new, second)):
                value["checks"].append({"check": name, "status": "PASS", "observed_at": value["observed_at"], **fields})
            previous = periodic.make_snapshot(old, "fixture", "host", "scope", current=NOW)
            current = periodic.make_snapshot(new, "fixture", "host", "scope", current=after)
            self.assertIn(name, periodic.compare(previous, current, clock=after)["changed"])

    def test_explicitly_unreadable_protection_is_a_gap_on_first_run(self):
        value = collected()
        value["checks"][0]["protection_status"] = "NOT RUN"
        result = periodic.make_snapshot(value, "fixture", "host", "scope", current=NOW)
        self.assertIn("sip", periodic.coverage(result))

    def test_missing_known_protection_fields_cannot_keep_a_green_collection(self):
        value = collected()
        value["checks"][0].pop("enabled")
        result = periodic.make_snapshot(value, "fixture", "host", "scope", current=NOW)
        self.assertEqual("PARTIAL", result["checks"]["sip"]["collection_status"])
        self.assertEqual("PARTIAL", result["checks"]["sip"]["status"])
        for name in ("defender", "firewall", "bitlocker_status", "secure_boot"):
            value = collected()
            value["checks"][0] = {"check": name, "status": "PASS", "observed_at": NOW.isoformat(), "data": None}
            result = periodic.make_snapshot(value, "fixture", "host", "scope", current=NOW)
            self.assertEqual("PARTIAL", result["checks"][name]["collection_status"])

    def test_first_snapshot_does_not_attest_host_or_grant_authority(self):
        value = snap()
        periodic.validate_snapshot(value)
        self.assertEqual("NOT ATTESTED", value["trust_assessment"])
        self.assertNotIn("Unstable PID CPU text", json.dumps(value))
        self.assertNotIn("approved", value)

    def test_boolean_schema_and_stale_future_input_rejected(self):
        for stamp in (NOW - dt.timedelta(hours=3), NOW + dt.timedelta(seconds=1)):
            with self.assertRaises(ValueError):
                periodic.make_snapshot(collected(stamp), "fixture", "host", "scope", current=NOW)
        value = collected()
        value["schema_version"] = True
        with self.assertRaises(ValueError):
            periodic.make_snapshot(value, "fixture", "host", "scope", current=NOW)

    def test_disabled_protection_is_new_concern_not_green(self):
        after = NOW + dt.timedelta(days=1)
        result = periodic.compare(snap(), snap(after, False), clock=after)
        self.assertTrue(result["notify"])
        self.assertEqual(["sip"], result["current_concerns"])
        self.assertEqual("PARTIAL", result["status"])
        self.assertEqual("NOT ASSESSED", result["verdict"])

    def test_persistent_failure_remains_visible_without_duplicate_notification(self):
        after = NOW + dt.timedelta(days=1)
        result = periodic.compare(snap(enabled=False), snap(after, False), clock=after)
        self.assertFalse(result["notify"])
        self.assertEqual(["sip"], result["persistent_concerns"])
        self.assertEqual("PARTIAL", result["status"])

    def test_missing_or_unreadable_check_never_becomes_improvement(self):
        after = NOW + dt.timedelta(days=1)
        for absent in (True, False):
            value = collected(after)
            if absent:
                value["checks"] = value["checks"][1:]
            else:
                value["checks"][0] = {"check": "sip", "status": "NOT RUN"}
            current = periodic.make_snapshot(value, "fixture-machine", "host", "scope-v1", current=after)
            result = periodic.compare(snap(enabled=False), current, clock=after)
            self.assertIn("sip", result["coverage_lost"])
            self.assertEqual([], result["observed_improvements"])

    def test_protection_visibility_lost_even_if_query_still_passes(self):
        after = NOW + dt.timedelta(days=1)
        value = collected(after)
        value["checks"][0] = {"check": "sip", "status": "PASS", "collection_status": "PASS"}
        current = periodic.make_snapshot(value, "fixture-machine", "host", "scope-v1", current=after)
        result = periodic.compare(snap(enabled=False), current, clock=after)
        self.assertIn("sip", result["coverage_lost"])
        self.assertEqual([], result["observed_improvements"])

    def test_no_change_keeps_gaps_visible_and_ignores_cpu_pid_churn(self):
        def with_gap(at, text):
            value = collected(at)
            value["checks"][1]["output"] = text
            value["checks"].append({"check": "account_security", "status": "NOT RUN"})
            return periodic.make_snapshot(value, "fixture", "host", "scope", current=at)
        after = NOW + dt.timedelta(days=1)
        result = periodic.compare(with_gap(NOW, "pid 1 cpu 8"), with_gap(after, "pid 99 cpu 50"), clock=after)
        self.assertFalse(result["notify"])
        self.assertEqual(["account_security"], result["current_gaps"])
        self.assertEqual("PARTIAL", result["status"])

    def test_machine_platform_scope_version_and_environment_mismatch_rejected(self):
        after = NOW + dt.timedelta(days=1)
        for field, other in [("machine_id", "other"), ("platform", "windows"),
                             ("architecture", "x64"), ("environment", "vm"),
                             ("scope_id", "other"), ("collector_version", "other")]:
            value = snap(after)
            value[field] = other
            value["sha256"] = periodic.digest(value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                periodic.compare(snap(), value, clock=after)

    def test_checksum_trust_claim_and_unknown_fields_rejected(self):
        for key, item in [("sha256", "0" * 64), ("trust_assessment", "SAFE"), ("approved", True)]:
            value = snap()
            value[key] = item
            with self.assertRaises(ValueError):
                periodic.validate_snapshot(value)

    def test_gap_in_runs_and_stale_current_snapshot_are_distinct(self):
        after = NOW + dt.timedelta(days=3)
        result = periodic.compare(snap(), snap(after), clock=after)
        self.assertTrue(result["notify"])
        self.assertIn("run_gap_exceeds_policy; not evidence of continuous monitoring", result["reasons"])
        with self.assertRaises(ValueError):
            periodic.compare(snap(), snap(after), clock=after + dt.timedelta(hours=3))

    def test_duplicate_checks_and_unknown_status_rejected(self):
        value = collected()
        value["checks"].append(copy.deepcopy(value["checks"][0]))
        with self.assertRaises(ValueError):
            periodic.make_snapshot(value, "fixture", "host", "scope", current=NOW)
        value = collected()
        value["checks"][0]["status"] = "clean"
        with self.assertRaises(ValueError):
            periodic.make_snapshot(value, "fixture", "host", "scope", current=NOW)

    def test_secret_and_raw_diagnostics_are_not_persisted(self):
        value = collected()
        value["checks"][1]["output"] = "password=sentinel-private-value"
        value["environment"] = {"TOKEN": "sentinel-private-value"}
        result = periodic.make_snapshot(value, "fixture", "host", "scope", current=NOW)
        self.assertNotIn("sentinel", json.dumps(result))

    def test_snapshot_is_exclusive_and_private_not_an_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "snapshot.json"
            periodic.write_snapshot(output, snap())
            original = output.read_bytes()
            if os.name == "posix":
                self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            with self.assertRaises(FileExistsError):
                periodic.write_snapshot(output, snap())
            self.assertEqual(original, output.read_bytes())
            self.assertEqual(snap(), audit.read_plan(output))

    def test_windows_firewall_and_bitlocker_regressions_are_observable(self):
        def windows(at, enabled):
            return {"schema_version": 1, "collector_version": "0.2.0", "platform": "windows",
                    "architecture": "x64", "observed_at": at.isoformat(), "checks": [
                        {"check": "firewall", "status": "PASS", "observed_at": at.isoformat(), "data": [
                            {"Name": "Public", "Enabled": "True" if enabled else "False"}]},
                        {"check": "bitlocker_status", "status": "PASS", "observed_at": at.isoformat(), "data": [
                            {"MountPoint": "C:", "ProtectionStatus": "On" if enabled else "Off"}]}]}
        after = NOW + dt.timedelta(days=1)
        previous = periodic.make_snapshot(windows(NOW, True), "fixture", "host", "scope", current=NOW)
        current = periodic.make_snapshot(windows(after, False), "fixture", "host", "scope", current=after)
        result = periodic.compare(previous, current, clock=after)
        self.assertIn("firewall", result["changed"])
        self.assertIn("bitlocker_status", result["changed"])

    def test_disappearing_defender_flag_is_lost_evidence_not_recovery(self):
        def defender(at, data):
            value = collected(at)
            value["checks"] = [{"check": "defender", "status": "PASS", "observed_at": at.isoformat(), "data": data}]
            return periodic.make_snapshot(value, "fixture", "host", "scope", current=at)
        after = NOW + dt.timedelta(days=1)
        result = periodic.compare(defender(NOW, {"RealTimeProtectionEnabled": False}),
                                  defender(after, {"AMRunningMode": "Normal"}), clock=after)
        self.assertEqual(["defender"], result["coverage_lost"])
        self.assertEqual(["defender"], result["unverified_prior_concerns"])
        self.assertEqual([], result["observed_improvements"])

    def test_fresh_wrapper_does_not_refresh_old_check_evidence(self):
        value = collected()
        value["checks"][0]["observed_at"] = (NOW - dt.timedelta(days=90)).isoformat()
        result = periodic.make_snapshot(value, "fixture", "host", "scope", current=NOW)
        self.assertEqual("PARTIAL", result["checks"]["sip"]["collection_status"])
        self.assertEqual("NOT ASSESSED", result["checks"]["sip"]["protection_status"])

    def test_unknown_windows_enum_is_partial_instead_of_guessing(self):
        value = collected()
        value["platform"] = "windows"
        value["checks"] = [{"check": "firewall", "status": "PASS", "observed_at": NOW.isoformat(),
                            "data": [{"Name": "Public", "Enabled": 2}]}]
        result = periodic.make_snapshot(value, "fixture", "host", "scope", current=NOW)
        self.assertEqual("PARTIAL", result["checks"]["firewall"]["collection_status"])


class BoundedIOTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX native pipe fixture")
    def test_unreapable_child_does_not_enter_an_unbounded_final_wait(self):
        class Child:
            returncode=None
            def __init__(self):
                r,w=os.pipe(); os.close(w); self.stdout=os.fdopen(r,"rb")
                r,w=os.pipe(); os.close(w); self.stderr=os.fdopen(r,"rb")
            def poll(self): return None
            def kill(self): pass
            def wait(self,timeout=None):
                if timeout is None: raise AssertionError("Unbounded wait")
                raise __import__('subprocess').TimeoutExpired("fixture",timeout)
        child=Child()
        with patch.object(audit.subprocess,"Popen",return_value=child):
            result=audit.run_bounded(["fixed-fixture-command"],0.01)
        self.assertTrue(result.unreaped)
        self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_collector_byte_budget_does_not_relax_plan_default_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory).resolve()/"collector.json"
            path.write_text(json.dumps({"padding":"x"*1_100_000}))
            with self.assertRaises(ValueError): audit.read_plan(path)
            self.assertIn("padding",audit.read_plan(path,max_bytes=4_194_304))

    def test_windows_utf16_and_utf8_bom_json_inputs_keep_strict_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "input.json"
            for encoding in ("utf-8-sig", "utf-16"):
                path.write_bytes('{"value":"\u041a"}'.encode(encoding))
                self.assertEqual({"value": "\u041a"}, audit.read_plan(path))
                path.write_bytes('{"value":1,"value":2}'.encode(encoding))
                with self.assertRaises(ValueError):
                    audit.read_plan(path)

    @unittest.skipUnless(os.name == "posix", "Native bounded pipe reader is macOS/POSIX-only")
    def test_stdout_and_stderr_limits_apply_while_reading(self):
        for descriptor in (1, 2):
            with patch.object(audit, "MAX_OUTPUT", 2048):
                result = audit.run_bounded([sys.executable, "-I", "-c", f"import os; os.write({descriptor}, b'x' * 65536)"], 3)
            self.assertTrue(result.output_limited)
            self.assertLessEqual(len(result.stdout), 2048)
            self.assertEqual(b"", result.stderr)

    @unittest.skipUnless(os.name == "posix", "POSIX pipe reader")
    def test_slow_collection_child_times_out_and_is_reaped(self):
        result = audit.run_bounded([sys.executable, "-I", "-c", "import time; time.sleep(5)"], 0.05)
        self.assertTrue(result.timed_out)
        self.assertIsNotNone(result.returncode)

    def test_duplicate_keys_nonfinite_json_and_hardlinks_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "input.json"
            for text in ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}']:
                path.write_text(text)
                with self.assertRaises(ValueError):
                    audit.read_plan(path)
            path.write_text('{}')
            alias = path.parent / "alias.json"
            os.link(path, alias)
            with self.assertRaises(ValueError):
                audit.read_plan(path)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-relative parent walk")
    def test_replaced_parent_cannot_redirect_json_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            good, foreign = root / "good", root / "foreign"
            good.mkdir(); foreign.mkdir()
            (good / "input.json").write_text('{"source":"authorized"}')
            (foreign / "input.json").write_text('{"source":"foreign-sentinel"}')
            original_open = os.open
            swapped = False
            def race(path, flags, *args, **kwargs):
                nonlocal swapped
                if path == "input.json" and kwargs.get("dir_fd") is not None and not swapped:
                    swapped = True
                    good.rename(root / "moved")
                    good.symlink_to(foreign, target_is_directory=True)
                return original_open(path, flags, *args, **kwargs)
            with patch.object(audit.os, "open", side_effect=race):
                self.assertEqual({"source": "authorized"}, audit.read_plan(good / "input.json"))


if __name__ == "__main__":
    unittest.main()
