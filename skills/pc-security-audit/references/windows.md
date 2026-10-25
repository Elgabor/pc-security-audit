# Windows audit

Use native PowerShell (5.1+ or 7+) without profiles, execution-policy bypasses,
module installation, or automatic elevation. `scripts/windows_collect.ps1`
returns local metadata; unavailable checks are NOT RUN rather than false
evidence of missing protection. Apply a reasonable caller timeout from the
harness, for example 150 seconds, and report incomplete results.
The collector creates its own jobs with a per-check timeout (default 8 seconds),
a total collection budget (default 110 seconds), and diagnostic streams kept
separate from JSON. Stop/Remove applies only to its own jobs. External termination
can still prevent final output: report an incomplete run.
It uses modules from system paths and serializes enums as text. A timeout does
not stop user processes. Exit 1 means failed checks; 2 means incomplete coverage.
If policy blocks the file, report NOT RUN: use only interactive checks permitted
by the administrator, without bypassing policy. PowerShell in WSL/Linux does
not establish access to the actual Windows host. Also read [checks.md](checks.md)
and [incident.md](incident.md) for full prevention or incident recovery.

## Domains

- **System:** version/build/architecture and actual release support; compare
  updates against current Microsoft documentation. A hotfix list does not prove
  all software is current. No updates or restarts during the audit.
- **Defender:** interpret `Get-MpComputerStatus`; engine, signatures, real-time,
  cloud, and tamper protection. Passive mode can result from another antivirus:
  verify actual protection without starting two engines simultaneously.
- **Exclusions:** the collector returns counts, not paths/processes or other
  potentially private values. For targeted verification, use authorized UI and
  report only the outcome relevant to the suspicious target.
- **Firewall:** `Get-NetFirewallProfile`; distinguish profiles and rules from
  effective policy (`-PolicyStore ActiveStore`) and actual reachable traffic.
  `Get-NetTCPConnection` shows a connection snapshot rather than machine history.
  Consider local bind addresses and UDP; the collector's sample does not prove
  completeness.
- **Hardware:** Secure Boot, Memory Integrity/HVCI, and driver requirements.
  An unavailable UEFI check is NOT RUN; do not propose disabling protection
  to hide incompatibilities or warnings.
- **Encryption:** `Get-BitLockerVolume`, selecting MountPoint,
  VolumeStatus, ProtectionStatus, EncryptionMethod, EncryptionPercentage.
  Do not enumerate KeyProtector, RecoveryPassword, or `manage-bde -protectors -get`.
  Verify with the user that recovery is accessible without reading the key.
  Distinguish Device Encryption from availability of BitLocker UI.
- **Persistence:** tasks (`Get-ScheduledTask`), services (`Get-Service`), and
  local WMI (`Get-CimInstance` in `root/subscription`). Names/counts are insufficient
  to assess targets and actions; use native UI/Autoruns already available and
  authorized for targeted checks. Do not print Actions, CommandLineTemplate,
  ScriptText, or full command lines that may contain secrets. For counts only,
  the collector requests `Get-CimInstance -KeyOnly`: avoid acquiring script bodies
  or templates even when they would not be printed.
- **Startup and browser:** Startup, Run/RunOnce, extensions, policies, remote
  services, users/groups, and administrative apps. A WMI consumer is not inherently
  malicious; do not assume a universal count of legitimate consumers. Also check
  UAC, RDP/SMB, SmartScreen/PUA, Credential Guard, application control, and ASR
  when relevant. Corresponding collector NOT RUN entries require native checks;
  they are not checks already completed.
- **Identity and cloud:** apply [checks.md](checks.md) to relevant accounts through
  authorized interfaces and nonsecret user confirmations. Do not access local
  password/cookie stores.
- **Backup:** verify availability, separation, encryption, and recovery using
  user-selected samples and an authorized destination. Data restoration and
  session recovery/revocation are separate checks.

## Scans

An AV scan can quarantine files and change state. If not already authorized,
include it in the plan with its effects and restarts. Do not confuse a status
query with a completed scan.

Defender Offline uses an environment outside the normal kernel; verify current
Microsoft requirements, WinRE, architecture, and active antivirus. The consulted
documentation excludes Windows ARM and Windows Server: do not claim universal
compatibility. It may require a restart and BitLocker recovery handling: plan
these effects without reading the key or implicitly suspending encryption.
A negative result does not rule out historical credential theft or cloud persistence.

## Cleanup candidates

For an absolute directory chosen by the user, use `Get-Item -LiteralPath` and
`Get-ChildItem -LiteralPath <directory> -Force`, limiting output to name, size,
attributes, and LastWriteTimeUtc. Exclude sensitive names and reparse points
before descending. Avoid `-Recurse` over an entire profile: it does not
automatically honor every permission or privacy boundary. Names are private;
minimize sharing and apply [workflow.md](workflow.md) before proposing removal.
Storage Sense, temporary-file cleanup, and app cleanup are proposals with stated
targets/effects rather than a generic space-recovery button.

Sources: [Defender status](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus),
[Defender Offline](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-offline),
[BitLocker status](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume),
[Get-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask),
[WMI persistence](https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times),
[access revocation](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access).
