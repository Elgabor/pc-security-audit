"""Native read-only skill discovery. No thread/model turn or config writes."""
import asyncio
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = (ROOT / "skills/pc-security-audit/SKILL.md").resolve()


async def main():
    process = await asyncio.create_subprocess_exec(
        "codex", "app-server", "--stdio", cwd=ROOT,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, limit=2 * 1024 * 1024)

    async def call(identifier, method, params):
        process.stdin.write((json.dumps({"id": identifier, "method": method, "params": params}) + "\n").encode())
        await process.stdin.drain()
        while True:
            line = await asyncio.wait_for(process.stdout.readline(), timeout=30)
            if not line:
                raise RuntimeError("app-server closed before response")
            item = json.loads(line)
            if item.get("id") == identifier:
                if "error" in item:
                    raise RuntimeError("native RPC returned error")
                return item.get("result", {})

    try:
        await call(1, "initialize", {"clientInfo": {"name": "pc-audit-discovery", "version": "0.1.0"}, "capabilities": {"experimentalApi": True}})
        process.stdin.write(b'{"method":"initialized"}\n')
        await process.stdin.drain()
        # This installed protocol has no perCwdExtraUserRoots field. Its
        # connection-scoped extra-root API loads source without installation.
        await call(2, "skills/extraRoots/set", {"extraRoots": [str(ROOT / "skills")]})
        result = await call(3, "skills/list", {"cwds": [str(ROOT)], "forceReload": True})
        selected = []
        errors = []
        for group in result.get("data", []):
            for item in group.get("skills", []):
                if item.get("name") == "pc-security-audit" or "pc-security-audit" in str(item.get("path", "")):
                    selected.append({"name": item.get("name"), "path": item.get("path"), "enabled": item.get("enabled")})
            errors.extend(x for x in group.get("errors", []) if "pc-security-audit" in str(x))
        passed = any(x["path"] and Path(x["path"]).resolve() == SKILL and x["enabled"] is True for x in selected) and not errors
        print(json.dumps({"status": "PASS" if passed else "FAIL", "skills": selected,
                          "skill_errors": errors, "model_turns": 0, "config_writes": 0,
                          "loading": "connection-scoped extra root; resolved canonical target"}, indent=2))
        return 0 if passed else 1
    finally:
        if process.stdin:
            process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=3)
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
