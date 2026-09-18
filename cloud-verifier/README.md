# Future central Microsoft assurance integration (design only)

A future central integration may support policy provenance, local-to-cloud correlation, cross-plane troubleshooting and Microsoft policy-intent versus observed-state reconciliation. It must operate outside endpoints so Microsoft Graph credentials, certificates and privileged identities are never stored with ESAF endpoint artifacts.

The intended boundary is narrow:

- retrieve explicitly approved Microsoft policy and assignment metadata through a centrally governed identity;
- record source, policy ID, assignment, retrieval time and mapping provenance;
- map selected Microsoft policy settings to existing local verification probes;
- correlate ESAF Run IDs with approved Microsoft evidence when that correlation answers a defined assurance question;
- preserve policy intent, endpoint observation and downstream compliance as separate evidence layers.

This design is not intended to reproduce Defender reports, recreate MDE incidents, recreate Advanced Hunting, replace vulnerability management or Secure Score, or claim Microsoft Defender for Endpoint Plan 2 functionality. Native Microsoft portals and services remain authoritative for their own management, telemetry, investigation, reporting and licensing boundaries.

ESAF 0.3.0 does not implement Microsoft policy ingestion, Graph access, cloud correlation, tenant configuration, remediation or a cloud verdict. Corporate-W11 1.1.0 remains a locally authored schema 1.0 comparison baseline. Any future integration must first validate the supported Microsoft API, least-privilege permissions, licensing, assignment-resolution behavior and policy-conflict semantics before changing the ESAF runtime contract.

Future cloud integration must use only APIs supported by the organization's actual Microsoft licensing and management configuration. Defender for Business supports Defender for Endpoint APIs for capabilities available in Defender for Business, but Microsoft documents Advanced Hunting as not included in Defender for Business. ESAF therefore does not depend on `runHuntingQuery`. Any future API integration must be capability-tested in the target tenant before becoming part of the runtime contract. See [supported Microsoft Defender for Endpoint APIs](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list) and [Microsoft Defender for Endpoint API access](https://learn.microsoft.com/en-us/defender-endpoint/api/apis-intro).
