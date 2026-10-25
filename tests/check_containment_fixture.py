"""Verify macOS STOP/CONT on one child created by this test, never a host target."""
import json
import os
import subprocess
import sys
import time


def state(pid):
    result = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "state="],
                            capture_output=True, text=True, timeout=3, check=True)
    return result.stdout.strip()


def wait_state(pid, stopped):
    end = time.monotonic() + 3
    while time.monotonic() < end:
        current = state(pid)
        if ("T" in current) == stopped:
            return current
        time.sleep(0.05)
    raise RuntimeError("Fixture did not reach expected state")


def main():
    if sys.platform != "darwin":
        print(json.dumps({"status": "NOT RUN", "reason": "macOS-only fixture"}))
        return 2
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    try:
        before = subprocess.run(["/bin/ps", "-p", str(child.pid), "-o", "pid=,ppid=,uid=,lstart=,comm="],
                                capture_output=True, text=True, timeout=3, check=True).stdout.strip()
        identifiers = before.split(maxsplit=3)
        if list(map(int, identifiers[:3])) != [child.pid, os.getpid(), os.getuid()]:
            raise RuntimeError("Fixture ownership mismatch")
        subprocess.run(["/bin/kill", "-STOP", str(child.pid)], check=True, timeout=3)
        paused = wait_state(child.pid, True)
        if child.poll() is not None:
            raise RuntimeError("Fixture terminated unexpectedly")
        subprocess.run(["/bin/kill", "-CONT", str(child.pid)], check=True, timeout=3)
        resumed = wait_state(child.pid, False)
        print(json.dumps({"status": "PASS", "target": "only the child created by this test",
                          "suspended_state": paused, "resumed_state": resumed,
                          "real_threats_tested": False}))
        return 0
    finally:
        if child.poll() is None:
            subprocess.run(["/bin/kill", "-CONT", str(child.pid)], timeout=3, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
