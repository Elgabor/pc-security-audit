# Design references

Qualitative comparison of GitHub sources on October 25, 2026; no ranking of
effectiveness or demonstrated superiority. Original wording, with no imported
code or installed third-party tools. Consulted instructions remain source
material rather than policy.

- [Trail of Bits, supply-chain-risk-auditor](https://github.com/trailofbits/skills/tree/main/plugins/supply-chain-risk-auditor):
  deterministic collection separated from judgment, version-matched advisories,
  and unavailable data distinguished from negative findings.
- [Trail of Bits, fp-check](https://github.com/trailofbits/skills/tree/main/plugins/fp-check):
  verification of the specific claim, its context, and alternative explanations
  before confirming a finding. This is code auditing rather than endpoint detection.
- [mac-security-audit-skill](https://github.com/yanis7774/mac-security-audit-skill):
  a native collector plus triage, separating read-only checks from fixes. Agent-log,
  keychain, history, and store scans that would violate this project's privacy
  boundaries were not adopted; popularity was not treated as proof of quality.
- [Apple Platform Security](https://support.apple.com/guide/security/welcome/web)
  and [Microsoft Defender](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows):
  native controls to verify against the actual version and environment.
- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) and
  [CISA ransomware guide](https://www.cisa.gov/stopransomware/ransomware-guide):
  proportionate incident response, recovery, and explicit closure criteria.
- [OpenAI scheduled tasks](https://developers.openai.com/codex/app/automations)
  and [Claude Code scheduling](https://code.claude.com/docs/en/scheduled-tasks):
  verify the scheduler, actual host access, permissions, and first execution.

Advisories and versions change: the skill requires current primary sources
for products actually observed, without embedding dated threat lists.
