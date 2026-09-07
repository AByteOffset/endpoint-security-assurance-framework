# Project scope

ESAF certifies and recertifies Windows endpoint security assurance. New provisioning is the primary use case. Existing endpoints, approved legacy clients, fleet assessments, baseline updates and engine/test updates use the same versioned assessment model.

Foundation includes desired-state definitions, local effective-state collection, deterministic verdicts, protected local evidence/history, installation/detection scripts and Intune Custom Compliance. Corporate-W11 1.0.0 requires client build 22000+. An unsupported device returns REVIEW with NOT_APPLICABLE controls. To assess approved older Windows clients, author a separately reviewed baseline, add its profile to the appropriate controls, validate provider availability in a lab and adapt the deployment/compliance version contract.

Out of scope: EDR, SIEM, SOC investigation, incident response, vulnerability scanning, Intune or Defender portal replacement, dashboards, React, web servers, databases, AI, KQL assistants, case management, inventory portals, generic BAS, permanent services and automated remediation. No cloud integration is implemented.

STANDARD is production-oriented: configuration/effective-state checks now; connectivity, explicitly approved harmless canaries and Microsoft-supported functional tests later. EICAR, Atomic Red Team, malware simulation, protection disabling and arbitrary commands are forbidden.

DEEP is a future separate opt-in for labs, pilot security devices, controlled troubleshooting and policy validation. Possible reviewed integrations include Microsoft's EDR detection test, EICAR, selected ASR demonstrations and reviewed Atomic Red Team atomics. There is no Deep execution path in 0.1.0.
