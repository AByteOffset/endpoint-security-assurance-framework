# Future central MDE cloud verifier (design only)

A central service identity, outside endpoints, will call Microsoft Graph Security `POST /security/runHuntingQuery` with the application permission `ThreatHunting.Read.All` and administrator consent. Select least privilege and central secret/managed identity management appropriate to deployment. Graph credentials must NEVER exist on ESAF endpoints.

The verifier may correlate approved ESAF Run IDs with DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents and DeviceNetworkEvents. Correlation needs device identity, explicit approved canary/event design, bounded query windows and measured telemetry latency; a local Run ID by itself does not guarantee MDE will capture it. Separate local completion time, first cloud observation and timeout/absence. Missing telemetry must not automatically be interpreted as proof a control failed.

No Graph client, credentials, Azure components, query executor or cloud assurance verdict are implemented here. Future results should retain local assessment and cloud observation as separate evidence layers.

Reference: [Microsoft Graph runHuntingQuery](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0).
