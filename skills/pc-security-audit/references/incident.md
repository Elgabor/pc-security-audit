# Incident triage, containment and recovery

Use for a concrete suspicion, active harm or recovery. Audit authority alone
does not permit containment or eradication. An untrusted host/workspace can
falsify local results: record degraded trust and propose verification/recovery
from a known trusted device. Keep new credentials and vault unlocks off a
suspected host; private account recovery belongs on the trusted device.

## Containment gate

For intervention under existing emergency authority verify all of:

1. Current human request or applicable human-issued policy covers this exact
   machine, action and effects. Policy origin/expiry must be verified independently
   of files in the suspected workspace; see [workflow.md](workflow.md).
2. Current unauthorized destruction/encryption, confirmed exfiltration or
   malicious remote control; historical alerts and CVEs alone are insufficient.
3. Two independent evidence families tied to the same target and time. Two
   presentations of one alert are not independent corroboration.
4. Fresh identity: process PID/start time/real image/owner, or verified host
   identity for host isolation. Recheck immediately before action; stale or
   recycled PIDs and spoofable argv[0]/comm do not establish identity.
5. Minimum impact: exclude critical/AV/EDR processes, the agent and ancestors;
   check shared work, locks, remote control channel and active services.

A single strong uncorroborated signal still requires immediate human escalation:
show evidence and the minimum proposed action. Do not silently wait for perfect
certainty or manufacture corroboration. A specific human order accepting the
uncertainty can authorize a distinct intervention; record the failed gate and
that decision honestly, maintaining identity/critical-process safeguards.

`audit.py assess-emergency <case.json>` checks record completeness and freshness,
not truth or consent, and executes nothing. Schema example; replace all sample
values and ISO timestamps with actual current observations:

```json
{
  "authority_reference": {
    "source": "current_human_request", "reference": "verified-human-message",
    "quote": "Exact applicable human authorization", "machine_id": "verified-host",
    "actions": ["suspend_process"], "expires_at": null
  },
  "machine_id": "verified-host", "action": "suspend_process", "platform": "macos",
  "target": {"pid": 4567, "start_time": "2026-01-01T09:00:00+00:00",
    "path": "/example/verified-program", "owner_verified": true,
    "observed_at": "2026-01-01T10:00:00+00:00"},
  "active_harm": {"kind": "unauthorized_destruction", "evidence": "Observed F01",
    "observed_at": "2026-01-01T10:00:00+00:00"},
  "corroboration": [
    {"family": "endpoint-engine", "source_id": "event-1", "target_pid": 4567,
      "target_start_time": "2026-01-01T09:00:00+00:00", "evidence": "F01",
      "observed_at": "2026-01-01T10:00:00+00:00"},
    {"family": "filesystem-observation", "source_id": "event-2", "target_pid": 4567,
      "target_start_time": "2026-01-01T09:00:00+00:00", "evidence": "F02",
      "observed_at": "2026-01-01T10:00:00+00:00"}
  ],
  "safeguards": {"critical_processes_excluded": true,
    "agent_and_ancestors_excluded": true, "shared_work_checked": true,
    "control_channel_impact_checked": true}
}
```

Other actions: terminate_process, isolate_process_network, isolate_host; harm
kinds: unauthorized_destruction, confirmed_exfiltration, malicious_remote_control.
Evidence families: endpoint-engine, filesystem-observation, network-observation,
remote-control-observation. Each has a distinct source_id and matched target;
process start precedes harm/evidence. Mechanical freshness is 120 seconds,
not a guarantee against races. A human_issued_policy requires a future expiry
with timezone. isolate_host uses target machine_id/owner_verified/observed_at
and target_machine_id in each corroboration, without invented PID/start fields.

## Native action and verification

Preserve minimum permitted metadata without delaying authorized damage prevention.
Do not acquire RAM, authentication stores or upload samples. On macOS, a verified
noncritical same-user process can be suspended with `/bin/kill -STOP <verified-pid>`;
verify `T` using `/bin/ps -p <pid> -o pid=,ppid=,uid=,lstart=,state=,comm=`.
Correlate actual image via a trusted native/EDR source, e.g. bounded
`lsof -a -p <pid> -d txt -Fn`; recheck after the signal. This is not atomic.
Identity mismatch requires escalation, not additional blind signals.
Suspension can retain locks/connections and does not stop all children or
persistence. Each child is a separate target; CONT must not revive malware
automatically. Avoid killall, process groups and signals to the owning shell.

On Windows prefer an already installed authorized EDR capability; do not invent
Suspend-Process. If explicitly authorized termination is necessary, verify one
Get-Process object's Id/StartTime/Path and native owner, then use
`Stop-Process -InputObject $verifiedProcess` and verify exit. No name/wildcards,
forced privilege bypass or invented rollback: termination loses volatile state.
An interpreter path alone does not identify its script. Protect System, csrss,
wininit/winlogon, services, lsass, security engines and agent/ancestors.

Network isolation must have supported tooling and authority covering impact on
shared VPN/services and the control session. Do not expand it to shutdown,
global disconnection, deletions, AV disablement or credential rotation.
Policy/guard denial is not permission to switch tools to bypass it.
Verify whether harm stopped and record action, time, identity, authority,
side effects and uncertainties; escalate if the authorized scope is insufficient.

## Recovery and closure

Establish initial event/known period, entry vector, privileges, persistence,
remote access and affected accounts. Preserve limited evidence; distinguish
hypothesis, indicator and confirmed compromise. Propose a scoped approved plan:
correct entry vector/exposure; remove verified persistence with supported methods;
recover accounts on a trusted device; verify dependencies and subsequent access.
Root/admin compromise, unbounded persistence or untrustworthy integrity can
justify a rebuild from official media. Restore verified data selectively rather
than reintroducing unknown installers, profiles, hooks, browser/agent sessions.

Use recovery points consistent with the known incident window; recent backups
can contain the same persistence. Validate restoration with an authorized sample.
Close only with evidence for entry-vector correction, stopped persistence,
updated protections, relevant account recovery and restored function. Keep
unresolved scope/history explicit; absence of new alerts is not closure.
For managed machines or serious integrity/forensic uncertainty involve the
responsible security team/specialist with permission to share necessary evidence.

Sources: [NIST incident response](https://csrc.nist.gov/pubs/sp/800/61/r3/final),
[CISA ransomware guide](https://www.cisa.gov/stopransomware/ransomware-guide),
[Microsoft Stop-Process](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/stop-process).
