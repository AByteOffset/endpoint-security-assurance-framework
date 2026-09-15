# Project scope

ESAF is an Endpoint Security Policy Assurance Framework around native Microsoft security controls. Microsoft Defender and Intune remain the management and control planes, and Microsoft Entra remains the identity and access control plane. ESAF independently verifies effective local Windows state, retains protected point-in-time evidence and supports post-deployment mismatch or drift investigation. It does not configure Microsoft security controls or replace native management, compliance, reporting, attestation or Conditional Access.

The current engine uses Corporate-W11 1.1.0 as its locally authored, reviewed schema 1.0 comparison baseline. ESAF does not yet ingest authoritative Microsoft policy intent. The existing fourteen controls are local verification probes for Microsoft-managed endpoint security capabilities. New provisioning, existing endpoints, approved legacy clients, fleet assessments, baseline updates and engine/test updates use the same versioned assessment model.

Foundation includes local comparison criteria, effective-state collection, deterministic verdicts, protected local evidence/history, installation/detection scripts and an optional Intune Custom Compliance adapter proven in a one-device pilot. Corporate-W11 1.1.0 requires client build 22000+. An unsupported device returns REVIEW with NOT_APPLICABLE controls. To assess approved older Windows clients, author a separately reviewed baseline, add its profile to the appropriate controls, validate provider availability in a lab and adapt the deployment/compliance version contract.

Out of scope: EDR, SIEM, SOC investigation, incident response, vulnerability scanning, Intune or Defender portal replacement, dashboards, React, web servers, databases, AI, KQL assistants, case management, inventory portals, generic BAS, permanent services and automated remediation. No cloud integration is implemented.

STANDARD is production-oriented: configuration/effective-state checks now; connectivity, explicitly approved harmless canaries and Microsoft-supported functional tests later. EICAR, Atomic Red Team, malware simulation, protection disabling and arbitrary commands are forbidden.

DEEP is a future separate opt-in for labs, pilot security devices, controlled troubleshooting and policy validation. Possible reviewed integrations include Microsoft's EDR detection test, EICAR, selected ASR demonstrations and reviewed Atomic Red Team atomics. There is no Deep execution path in 0.1.0.

Milestone 3 adds nine read-only local security controls to the original five. No agent, dashboard, database, remediation, attack simulation or online MDE verifier is included.
