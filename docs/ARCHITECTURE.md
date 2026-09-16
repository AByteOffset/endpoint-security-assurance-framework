# Architecture

## Product boundary

Microsoft Defender and Intune remain the native Microsoft management, configuration and reporting planes for applicable endpoint security controls. ESAF independently observes selected effective Windows and platform state. Entra Conditional Access can consume Intune compliance for access decisions. ESAF is a privileged local assessor around those planes; it is not a Microsoft policy deployment system, compliance replacement, attestation authority or Conditional Access decision engine.

The current architecture is:

```text
Approved organizational security policy
  -> Microsoft Defender / Intune configuration and deployment
  -> effective Windows endpoint state
  -> independent ESAF local verification probes
  -> comparison with reviewed ESAF schema 1.0 criteria
  -> protected evidence / assessment history
  -> optional downstream integrations
```

Corporate-W11 1.1.0 remains the schema 1.0 `baseline` runtime concept. “Verification profile” is forward-looking architecture terminology only; no runtime field, file or schema is renamed. The baseline is locally authored and reviewed and is not authoritative policy intent imported from a Microsoft service.

Milestone 4 implements a deliberately narrow central policy-intent POC. It reads one explicitly selected Intune Defender Antivirus policy through Microsoft Graph, validates one AllowRealtimeMonitoring setting and supported group assignment, and reconciles that intent with `ESAF-AV-002` in a supplied evidence file. This separate reconciliation contract does not change schema 1.0 or the endpoint verdict. It remains separate from endpoint credentials, remediation, native Microsoft reporting and access-control decisions. See [the Milestone 4 POC contract](MILESTONE4_POLICY_INTENT_POC.md).

`src/ESAF.psm1` loads the module components. `Core` orchestrates; `Controls` validates baseline/control data and applicability; `Evidence` performs approved read-only collection; `Verdict` compares normalized values and aggregates; `Reporting` publishes artifacts; `Utility` supplies platform detection, safe JSON reads and random IDs. `tools/Invoke-ESAF.ps1` alone formats human console output.

When selected as the delivery mechanism, Intune deploys files under Program Files and starts validation as SYSTEM in a 64-bit process. The runner loads all definitions before collection, detects Windows client/build applicability and generates a 128-bit random Run ID with .NET RandomNumberGenerator. All timestamps are UTC ISO-8601. Each applicable control collects only an allowlisted subset of local data. Provider errors are sanitized structured records; other controls continue.

Outputs under `C:\ProgramData\ESAF` are `result.json`, `evidence.json`, `ESAF.log`, `history/<RunID>/result.json` and `history/<RunID>/evidence.json`. The Global\ESAF.Execution.v1 named mutex now coordinates installation, validation and uninstall across SYSTEM/admin sessions, with a 30-second default timeout (0-600 configurable) and finally release. Access is limited to SYSTEM/Administrators. Nested validation from an installer is reentrant on the same thread; each acquisition is released. Abandoned ownership is recoverable on the next acquisition. The existing exclusive run.lock file remains a second publication guard. Temporary JSON files are read back and validated before atomic replacement, and removed in finally blocks. There is no automatic history retention deletion.

Latest JSON files are individually replaced atomically. There is no cross-file transaction: history is written first, then evidence, then result, log and registry. Registry publication is the last successful execution step. Consumers require matching Run IDs and versions; a partial publication cannot be reported as a current successful install. Detailed evidence is never stored in the registry. Disk/registry/platform/input failures terminate execution; security provider errors are control results.

The eight registry fields are EngineVersion, BaselineName, BaselineVersion, LastRun, LastRunId, Status, CriticalFailures and HighFailures. The shared installed ResultContract helper validates the fourteen-control 1.1.0 result, expected/observed consistency, counters, timestamps and all eight registry fields. Discovery additionally inspects file ACLs and never collects live security state. A future central integration could correlate the Run ID and policy provenance without distributing cloud identities to endpoints. It must complement rather than reproduce native Defender reporting. See [future cloud design](../cloud-verifier/README.md).

Milestone 2 staging uses an explicit production allow-list and hash manifest. Bootstrap integrity/lock helpers are fixed code, never manifest-sourced commands. Installation is idempotent but not transactional: partial program-file copying produces execution failure and requires a retry. The mutex prevents cooperating 0.1.1 and 0.2.0 writers from racing; an older 0.1.0 process does not participate, so stop manual old-version validation before the pilot upgrade. ProgramData history is preserved during update/uninstall unless purge is explicit.

PENDING is a security verdict, never PASS. A completed PENDING run can satisfy application installation detection while failing assurance compliance. Foundation does not retry automatically; newly provisioned clients need a later explicit run after security convergence. Only unknown observations under explicit -Provisioning can become PENDING; confirmed mismatches and collection errors retain their failure semantics.

Recommended future convergence mechanism: an explicitly assigned Intune orchestration policy runs a bounded read-only recertification script after provisioning. It reads the last result and versions, retries only an approved PENDING/provisioning condition, and uses an administrator-defined deadline and maximum attempt count (for example three attempts within two hours). Each attempt has a new Run ID; lightweight attempt metadata records reason/count/deadline. Stop on PASS, confirmed failure, version change, deadline or attempt limit; surface unresolved convergence for review. Intune controls execution timing, so no local service, permanent agent or automatic installer failure is required. The policy must exclude functional execution from retries. Do not implement this scheduler or attempt-state schema in foundation. A separate CertificationFreshness compliance attribute can inform a future explicit recertification policy but never implicitly triggers Win32 reinstallation.

Milestone 3 adds ExpandedProviders.ps1 behind the existing code-owned provider registry. IDs DISK/HW/ASR map to disk/hardware/asr directories. Corporate-W11 1.1.0 adds securityIntelligenceMaxAgeHours (integer 1-720, shipped 72); the runner passes the validated baseline to the signature provider. UTC timestamp, assessment time, age and threshold are retained in evidence.json. Changes to baseline requirements need a baseline-version bump.

The result contract uses a code-owned fourteen-control catalog, independently checked against shipped definitions by tests. Aggregate certification considers required controls only; counters still include all controls. Only exclusion presence adds an explicit optional REVIEW path; successful ASR assessment is PASS for collection, not policy adequacy. High-level results contain normalized states and advisory guidance; safe per-profile/count/action details are in the protected evidence bundle. Eight existing compliance fields remain stable; overall ESAFStatus includes required disk/hardware controls but excludes optional ASR/exclusion findings from certification decisions even though separate category fields remain mde/defender/network. Compliance never imports the main module or calls providers.
