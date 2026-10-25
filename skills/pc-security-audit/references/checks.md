# Prevention, exposure and account checks

For a full audit cover the following areas using the applicable OS guide and
already authorized native/UI surfaces. These procedures add no automatic
collector coverage. Record method/time and unavailable checks explicitly.

| Area | Evidence and interpretation |
|---|---|
| System and updates | Actual OS/build, supported release, applicable patches and pending restart; include used apps, browsers, embedded runtimes and relevant containers. Installed, loaded, cached and published versions are different facts. |
| Privileges and lock | Everyday account type, administrative apps/harnesses, autologin, idle lock and authentication on wake. Account changes need a recovery path; preserve the only functioning administrator. |
| Protections | Provider/version, real-time state, exclusions, update information and last scan scope. Verify freshness against vendor updates/policy; a recent date or enabled flag alone proves neither effective coverage nor innocence. |
| Execution and privacy | Trusted app/update origin, browser protections, remote access, OS permissions and extensions. Signature/notarization is one signal; unknown names or unsigned software alone do not establish malware. |
| Backup and recovery | Availability, separation, encryption and a restore test with an authorized sample/destination. Sync alone does not establish an independent recoverable backup. Keys stay private. |
| Identity | Relevant accounts and grants only, as below; computer state does not establish cloud account security. |

On macOS distinguish SIP/Gatekeeper/FileVault/firewall from XProtect availability,
updates and relevant detections. No universal XProtect scan command is assumed.
On Windows identify the primary AV and Defender mode; passive Defender can be
legitimate. Separate realtime/cloud/tamper status, signatures, UAC, Secure Boot,
BitLocker, HVCI and SmartScreen/PUA/application control as supported. Evaluation
is not enforcement. ASR/Controlled Folder Access need compatibility and workload
testing before blocking. Scans that quarantine, updates and restarts have effects
and require authority; they are not read-only status queries.

## Version, advisory and exposure

For each pertinent software/service instance establish:

1. Observed product/version and provenance, actual mode of use and loaded instance.
2. Primary vendor/CSIRT advisory with date/revision, affected configurations,
   prerequisites, fix and distributor backports. Applicability is YES/NO/UNKNOWN
   with a reason; missing data is UNKNOWN rather than a negative finding.
3. Process/owner, TCP/UDP listener and bind; correlate firewall, proxy, container
   mapping, tunnels and forwarding to classify loopback/LAN/public/UNKNOWN.
   Wildcard bind does not prove Internet reachability; loopback may be proxied.
   An interpreter installed as a CLI does not establish a vulnerable HTTP path.
4. Known/unknown exposure period and accessible nonsecret evidence of activity.
   Separate advisory applicability, suspicious activity and confirmed intrusion.

Passive examples, within scope: `lsof -nP -iTCP -sTCP:LISTEN` on macOS;
`Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess`
on Windows; `docker ps --format '{{.ID}} {{.Image}} {{.Ports}}'` only with an
already authorized daemon/context. Inspect selected fields, not environment,
compose or raw logs. Do not probe third parties or start exposed services as a test.

Prioritize actual reachability, privileges, impact and known exploitation from
primary advisories/[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
CVSS alone does not order interventions; absence from a database does not refute
a flaw. An urgent patch proposal does not require evidence of active harm.
After approved work verify the loaded instance, required restart and residual
exposure, without declaring a mitigation equivalent to a fix without evidence.

## Accounts and phishing

Select only relevant email/device/cloud/AI/repository/backup accounts. Use
official UI or existing authorized interfaces with nonsecret fields; the user
performs login, passkey/OTP and recovery steps privately. Do not capture secrets,
QRs, recovery codes or full pages containing them. User confirmations are declared
evidence, not observed technical validation.

Check phishing-resistant MFA/passkeys where available, privately verified
password hygiene, available recovery, recognized activity/devices and relevant
grants/scopes/background access. Review mail forwarding/delegation/rules only
when pertinent, without reading messages. Browser sessions, OAuth grants,
refresh/access tokens, API keys and service identities have distinct revocation
semantics. A password change does not prove all accesses ended. API activity,
resources or unusual consumption require the relevant account scope; never read
key values or unrelated financial history.

For suspicious requests establish what already happened: viewed/clicked,
downloaded/executed, authentication accepted, data entered or grant issued.
Verify sender/domain/publisher, user initiation and an independent trusted
channel. HTTPS, logos, caller ID, legitimate login pages and readable prose
do not establish the request's legitimacy. Fake CAPTCHA, updates and disk
cleanup can ask for Terminal, Script Editor or remote-control permissions.
Do not execute the lure or open suspicious attachments/links to reproduce it.
Use OS/app updaters and already known official channels; private URLs never
belong in public searches. This is case review, not a mail scan or web filter.

For likely exposure use [incident.md](incident.md): recovery on a trusted device,
scoped revocation/rotation, dependency/continuity checks and subsequent-activity
verification. Preserve local prohibitions on credential modification; coordinate
private human steps where necessary. Account recovery and endpoint remediation
have separate completion criteria.

Sources: [Apple security](https://support.apple.com/guide/security/welcome/web),
[Microsoft Defender](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows),
[OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html),
[session revocation](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access).
