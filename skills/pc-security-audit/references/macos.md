# macOS audit

## Baseline and protections

Use `scripts/audit.py collect` for version, architecture, SIP/Gatekeeper/
FileVault/firewall status, disk space, memory pressure, process snapshots without
arguments, and metadata for LaunchAgents/Daemons and agent-extension directories.
The helper does not query the keychain, perform AV scans, or certify absence of
malware. Run it with `python3 -I -S -B` from a trusted copy, without elevation.
The home directory comes from the system account database; ambiguous user or
elevation context makes the personal inventory NOT RUN. Follow
[checks.md](checks.md) for full checks and [incident.md](incident.md) for incidents.

Then verify missing domains through native interfaces:

- Updates: version/build, applicable Apple security releases, pending restart,
  and updates for apps/runtimes actually used. Browse only public sources;
  researching patches does not authorize installation.
- Protections: interpret output rather than the exit code. `spctl --status`
  is not an XProtect scan or a check of every app or script.
- FileVault: check status and ask whether recovery was tested; do not request
  that the key be displayed or copied. Hardware encryption and FileVault are
  distinct layers on Apple silicon/T2.
- Privacy: System Settings > Privacy & Security; Full Disk Access, Accessibility,
  Screen Recording, and Automation for terminals, editors, harnesses, scanners,
  and remote-access apps. Record names/scope, not user data.
- Login and background: System Settings > General > Login Items & Extensions;
  compare with metadata from `~/Library/LaunchAgents`, `/Library/LaunchAgents`,
  and `/Library/LaunchDaemons`. Do not load or unload jobs during the audit.
  Also check privileged helpers, cron/periodic, shell startup, and IDE extensions
  when relevant: these remain explicitly NOT RUN in the collector.
- Device management: profiles, system/network extensions, VPN/proxy, and sharing.
  An unfamiliar profile is not necessarily malicious; verify organizational
  ownership and origin before proposing removal.
- Network: inbound firewall, listening services, and outbound traffic are distinct
  checks. Correlate PID and executable image; minimize IPs/domains in reports.
- Browser: extensions, permissions, policies, and synchronization; do not open
  databases, cookies, passwords, or complete profiles. Use only authorized UI.
- Identity and cloud: apply [checks.md](checks.md) to relevant accounts; login
  and sensitive verification steps remain private to the user. Do not infer
  account security from the Mac's protection status.

## Targeted investigation

For a specific suspicion, correlate AV/EDR detections, path, signature, origin,
parent process, connections, persistence, and harm. Do not search for secrets
or inspect memory dumps. A valid signature does not prove harmlessness; an
unsigned program, a new job, or high CPU usage does not prove compromise.

KnockKnock/BlockBlock/LuLu, when already installed and authorized, cover
persistence inventory, new events, and outbound network activity respectively.
Launching them may require Full Disk Access, other permissions, or external
lookups: do not grant these implicitly. No installation or sample uploads
during the audit.

## Backup and recovery

Check backup availability, separation, encryption, and date without reading
personal contents. A restore test uses sample files chosen by the user and an
authorized destination. A synchronized iCloud folder does not establish recovery
independent of deletion/ransomware. During a rebuild, do not indiscriminately
restore hooks, profiles, and sessions.

Sources: [Apple Platform Security](https://support.apple.com/guide/security/welcome/web),
[Malware](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web),
[FileVault](https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785/mac),
[configuration profiles](https://support.apple.com/guide/personal-safety/review-and-delete-configuration-profiles-ips327569a75/web).
