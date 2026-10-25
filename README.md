# PC Security Audit

An agent skill for macOS/Windows security audits, coding-agent permission reviews,
daily checks, and interventions within human authorization. The portable skill
directory is `skills/pc-security-audit/`: 12 files, with no external Python dependencies.

## Usage

```text
Use $pc-security-audit to check this computer's security and coding agents.
Explain verified findings, coverage gaps, and the highest-priority actions.
```

The harness must first discover the skill in a supported location. Copy
`skills/pc-security-audit/` to the harness's user-level skill directory:

| Harness | Skill directory |
|---|---|
| Codex | `~/.codex/skills/pc-security-audit/` |
| Claude Code | `~/.claude/skills/pc-security-audit/` |
| Pi | `~/.pi/agent/skills/pc-security-audit/` |
| OpenCode | `~/.config/opencode/skills/pc-security-audit/` |

When using a shared library, promote the reviewed version to its canonical
runtime source and generate views through the library's manager. This repository
contains portable regular files, without links to personal paths. Verify
discovery in a fresh session: files being present does not prove loading or
tool availability. Changes to the public source require explicit promotion
to runtime copies; there is no automatic synchronization.

## Daily audit setup prompt

```text
Use pc-security-audit, already provided in this harness, to prepare a daily
security check of my computer. Read its references/periodic.md. Verify the
actual reachable machine, the skill, and the supported local scheduler.
Run the initial read-only audit, agree on a private report directory, and show
coverage, metadata processed by the AI provider, permissions, and configuration.
Propose 09:00 daily in the detected local timezone. After my review, enable the
routine without duplicates and separately verify its first automatic execution.
Each run must explain changes, open findings, up to three priority actions,
and checks that could not run. Preserve existing permissions and write only
the agreed reports. Actions affecting the computer require authorization.
If no suitable scheduler is available, explain the requirement and leave the
audit available for manual use.
```

## Limitations and development

The two Python helpers require Python 3.11+; the Windows collector requires
PowerShell 5.1+ or 7+. Missing runtimes produce NOT RUN, without implicit
installation. Helpers collect metadata or validate records; they do not install
protections or perform remediation. Saving a report to disk does not make
analysis through an AI provider entirely local. Secrets and authentication
stores are excluded.

A daily audit is not continuous detection and does not certify absence of
compromise. Native Windows execution, real scheduled runs, and behavior with
different users require specific validation; helper tests do not replace it.
No public license is assigned implicitly.

```text
python3 -B -m unittest discover -s tests -v
python3 -B tests/check_codex_discovery.py
```

Tests and discovery checks stay in the development project, outside the installed
skill package. [SOURCES.md](SOURCES.md) lists the design references; no third-party
skill code was imported. Validation distinguishes completed and unperformed
checks; static validation does not establish detection effectiveness against
real threats.
