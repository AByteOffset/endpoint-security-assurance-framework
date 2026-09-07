# ESAF DEVELOPMENT RULES

## Safety
- Standard validation is read-only except explicitly approved harmless temporary canaries.
- Never disable Defender, Tamper Protection or firewall protection, weaken security policies, create Defender exclusions, or modify ASR configuration.
- Never remediate automatically or run malware.
- Never run EICAR or Atomic Red Team in Standard mode.
- Never execute arbitrary commands sourced from JSON/YAML control definitions.
- Never store Microsoft Graph secrets, client secrets, certificates, or privileged API credentials on endpoints.
- Temporary artifacts require deterministic cleanup.

## Engineering
- Use PowerShell, compatible with Windows PowerShell 5.1, and approved Verb-Noun names.
- Core functions return structured objects; no Write-Host in reusable core functions.
- Separate evidence collection, control definitions, implementation, and verdict calculation.
- Use stable control IDs, modular architecture and Pester tests. Validate all JSON.
- Security-critical decisions must be explainable from evidence.
- Verdicts: PASS, REVIEW, FAIL, PENDING, NOT_APPLICABLE; control collection can return ERROR.
- Critical failures override numeric scores.
