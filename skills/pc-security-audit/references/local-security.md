# Local skill, dependency, and harness inspection

This module is local and offline. It does not query cloud accounts, deploy
services, launch discovered code/MCP servers, or install scanners. Source-code
reads require an explicitly selected skill/source directory; metadata-only
audits do not implicitly authorize content scanning. Keep authentication and
conversation stores excluded. Never give raw scanner reports to the model.

## Native macOS baseline

`audit.py collect` now reads three additional nonsecret settings through a
fixed native firewall query and Foundation queries: firewall stealth mode, screensaver password, and
password grace period. The default grace comparison is the mSCP recommended
five seconds. Each record identifies its NIST mSCP reference rule and method; this is a selected
baseline, not full NIST/CIS compliance or proof of runtime enforcement.
Unset, unrecognized, inaccessible, or elevated/ambiguous user states are NOT RUN.
Only managed screensaver values are assessed; unmanaged preferences are PARTIAL
because they may not describe the actual lock screen. Grace assessment also
requires a managed enabled password requirement; stealth assessment requires an
enabled firewall. Managed/DDM behavior and actual enforcement need native/UI verification.
No downloaded mSCP check/fix scripts or profiles are executed. Existing SIP,
Gatekeeper, FileVault, firewall, patch and recovery checks remain separate.

The collector version changes to 0.3.0: review incompatible previous snapshots
instead of silently accepting a new healthy baseline. Periodic snapshots retain
only typed new facts, so missing preferences cannot appear as an improvement.

## Offline source triage

```text
python3 -I -S -B <skill-dir>/scripts/local_security.py scan-skill --root <exact-real-source-directory> --scope-id <agreed-skill-alias>
```

The descriptor-based scanner is POSIX-only. Resolve the authoritative source
through the trusted library manager first; it refuses symlinked roots/parents
rather than following discovered links. It skips sensitive stores, symlinks,
hardlinks, binaries and dependency/cache directories and reports coverage gaps.
Limits: 128 source files, 256 KiB per file, 2 MiB total, 1,024 entries, depth 5,
five seconds and 200 findings. All omissions remain visible. Do not scan an
entire home, system directory or session archive.
The root must contain a regular single-link `SKILL.md`. Harness/config/library
roots and known conversation/configuration names are rejected or skipped, even
when they contain a marker file. Unicode Tags and variation selectors are
included in hidden-control indicators; a leading UTF-8 BOM is ignored.
Common emoji-adjacent variation selectors/joiners are excluded from that signal.
Extensionless text and common shell/PowerShell/JSX/TSX scripts are inspected.
Examined nonsensitive entry metadata also enters the fingerprint, so omitted
file changes can be visible. Excluded subtree contents and entries beyond the
budget are not traversed or monitored. Credential-like filenames are omitted
before content reads or fingerprinting.

Rules identify instruction override, download-to-shell, shell interpolation,
sensitive-store access, approval bypass and invisible controls. Output contains
relative filenames/line numbers and rule IDs, never matching lines or snippets.
These are review indicators, including possible quoted defensive examples;
corroborate them before calling a skill malicious or proposing removal. This
small local engine is not Cisco's scanner and does not provide equivalent coverage.
It always returns PARTIAL: the finite rules cannot establish clean source.

## Cisco Skill Scanner local report adapter

If an already trusted scanner is available, its use still needs source-read
scope and approval for any optional hosted judge, OSV lookup, or upload. For
this local-only audit keep external analyzers disabled; do not install the
scanner or start MCP servers automatically. Use the installed version's help
to obtain a local JSON export. Keep the raw report private and outside chat.

```text
python3 -I -S -B <skill-dir>/scripts/local_security.py cisco-report <absolute-local-report.json> --scope-id <agreed-skill-alias>
```

The adapter understands Cisco `ScanResult.to_dict()` and aggregate
`Report.to_dict()` exports. It retains severity counts, analyzers used, failed
analyzers, skipped skills, suppression counts and oldest evidence time. It
ignores `is_safe` as a verdict and does not echo titles, snippets, raw paths,
errors or metadata. Every scan timestamp must be present, have a timezone and
be within two hours; a fresh aggregate wrapper cannot refresh old scans.
High/critical findings are FAIL for the scanner review, not confirmed infection.
Missing analyzers, failures, unknown severities and hidden findings remain gaps.
Missing optional coverage fields also remain gaps; a complete export without
high/critical findings still returns PARTIAL because provenance and requested
analyzer coverage are not attested. No findings only describes that export.

## Dependency advisories without network access

```text
python3 -I -S -B <skill-dir>/scripts/local_security.py packages --inventory <absolute-package-lock-or-inventory.json> --advisories <absolute-local-osv-cache.json> --scope-id <agreed-package-scope>
```

Inventory accepts npm package-lock v2/v3, including scoped/transitive package
versions, or a minimized export:
`{"schema_version":1,"packages":[{"ecosystem":"npm","name":"example","version":"1.2.3"}]}`.
Other inventory ecosystems are PyPI and Go. Do not read .env, registry credential
files or session stores to generate it. No install/build/import is performed.

The local cache is `{"schema_version":1,"fetched_at":"<ISO-time-with-zone>","queried_packages":[{"ecosystem":"npm","name":"example","version":"1.2.3"}],"advisories":[<OSV-records>]}`.
`queried_packages` lists every exact package/version whose advisory query
completed, including queries returning no advisories. Missing inventory coverage
is PARTIAL; an unrelated cache cannot establish a negative result.
Obtain/update that public advisory data separately with authorization; the helper
has no downloader. Default maximum declared cache age is 24 hours, configurable
with `--max-cache-age-hours` (1–720). A timestamp is not an authenticity guarantee.
Caches older than 24 hours remain PARTIAL even when accepted for investigation;
snapshots preserve the source timestamp and declared age. The history's stricter
two-hour evidence policy can downgrade a package check sooner.
Inputs use the existing no-symlink/single-link regular JSON reader, max 1 MiB.

Matching supports explicit affected-version lists and stable numeric SEMVER
introduced/fixed/last_affected events. Prereleases, other range semantics,
malformed intervals and missing coverage remain unknown. Withdrawn advisories
are ignored; malformed records are counted as gaps without discarding valid matches.
PyPI names are normalized; version strings are not guessed or rewritten.
Nonidentical PyPI versions cannot establish a negative match from a version list.
Go module paths and stable `v`-prefixed installed versions are accepted; pseudo
versions remain unknown. npm aliases use their real package name; workspace/link
entries are skipped as gaps. No match means no match in this cache, not absence
of vulnerabilities. Empty inventory or missing cache coverage is PARTIAL. A
covered package with a successful empty advisory response can have no matches.
Limits also bound records, comparisons and findings. Larger inputs need a bounded
minimized export; do not relax the file safety checks to accept a large raw dump.

## Periodic use and local threads

All three commands emit snapshot-compatible observations on macOS/Windows,
including NOT RUN errors. Native Windows execution remains untested; source
triage itself is POSIX-only. A distinct agreed `--scope-id` per engine and target
is required; pass the identical scope to periodic.py. Missing/mismatched scopes
are rejected. Snapshots retain
whitelisted counts and evidence fingerprints, not snippets or full source/report
bodies. Fingerprints expose changes even when counts stay equal; they do not
attest host integrity or classify malware. Keep the detailed
current report in its approved local destination and preserve unresolved
findings; source/engine/version/coverage changes require interpretation.
Changed evidence fingerprints block automatic improvement claims. Indicator
counts remain current concerns even when the engine status is PARTIAL.
No disappearing `local_*` concern is automatically listed as an improvement;
it requires manual reassessment. Cisco fingerprints include skill identity and
suppression/failure/policy metadata. Triage fingerprints also bind the rule set
and limits; engine version changes invalidate old comparisons.

Inspect local threads/background tasks through the installed harness's native
listing interface only. Request IDs, status, working directory, timestamps,
owner and resolved permissions when available. Minimize identifiers and paths.
Inspect only workloads verified as local to this host. If the interface cannot
exclude hosted workloads without retrieving their data, record NOT RUN.
Do not read conversation bodies, messages, transcripts, authentication/session
databases, environment dumps or full process arguments. Record inaccessible
metadata as NOT RUN. A long-running task or broad permission is not by itself
malware. Explain active capabilities and suspicious corroborated changes;
never stop a thread, alter a harness or revoke access from an audit request.

Sources: [NIST mSCP](https://github.com/usnistgov/macos_security),
[Cisco scanner](https://github.com/cisco-ai-defense/skill-scanner),
[Cisco export models](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/models.py),
[OSV schema](https://ossf.github.io/osv-schema/).
