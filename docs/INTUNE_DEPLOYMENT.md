# Intune deployment and recertification

Pilot on an approved lab endpoint first. Use Microsoft Win32 Content Prep Tool to package the repository content (exclude .git, .tools, artifacts and tests), preserving src, controls, baselines, tools and intune/package. See [packaging](../packaging/README.md). Deploy as a required Win32 application with SYSTEM install behavior and a Windows 11 requirement. There is no service, scheduled task, Graph credential or policy modification.

Install command from a 32-bit Intune launch context:

```text
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File .\intune\package\Install-ESAF.ps1
```

From a 64-bit lab shell use powershell.exe normally. Apply the organization's signing policy. Installation copies the endpoint payload to Program Files/ESAF, restricts its ACL, imports the installed module and runs validation. Output remains ProgramData/ESAF with restricted ACLs. A successful report with PASS, FAIL, REVIEW or PENDING returns installation exit code **0**. Failed copy, invalid input, platform discovery or report/registry publication returns **1**. Security FAIL is never mapped to an installation failure.

Upload Detect-ESAF.ps1 as a custom detection script with 32-bit execution on 64-bit clients **No**. It emits a nonempty success string and exit 0 only when installed module/baseline versions, completed validation versions, status and registry Run ID match. It accepts completed security FAIL and PENDING as installed. Missing, malformed, version-mismatched or incomplete publication produces exit 1 without stdout. An old valid result remains detected; MaximumAgeHours has been removed. Completion time must still parse and must not be substantially in the future.

For baseline 1.1.0, publish a revised package and detection script with RequiredBaselineVersion=1.1.0. Similarly update RequiredEngineVersion after an engine/test change. A 0.1.0/1.0.0 certificate fails the revised detection even if installed files were copied earlier. Intune's next required-app evaluation reruns installation/validation. Exact version equality prevents accidental certification against a different baseline. Weekly reinstallation is intentionally removed: elapsed age is not an installation defect. Additional recertification requires an explicit future policy or a manual validation run.

Upload Compliance-Discovery.ps1 as a Windows Custom Compliance discovery script. Run as logged-on user **No**, run in 64-bit PowerShell **Yes**. Configure signature enforcement according to your signed deployment. Upload Compliance-Rules.json and assign the policy to the same pilot group. Discovery performs no security collection and emits one compressed JSON line. SYSTEM access is necessary because results are intentionally not readable by ordinary users.

Rules require ESAFStatus/MDEAssurance/DefenderAssurance/NetworkAssurance PASS and exact baseline/engine versions. Missing, unsupported-version or inconsistent results return PENDING and cannot satisfy the rules. Non-PASS group results report REVIEW. Intune compliance is binary; ESAF's richer verdict remains in local data and ESAFStatus. Discovery additionally returns CertificationFreshness=Fresh/Stale/Unknown, using MaximumAgeHours=168 only for this separate attribute. Stale does not overwrite a recorded PASS, FAIL or PENDING. The shipped rules deliberately contain no freshness requirement; administrators can later explicitly add a String/IsEquals/Fresh rule. This separation prevents an accidental compliance-driven weekly retry policy. Update the discovery version contract and rules operands with package/detection versions for each release.

PENDING during provisioning means evidence was unknown under explicit -Provisioning; installation may succeed but compliance does not. The current installer uses ordinary validation (unknown becomes REVIEW), while a manual provisioning run can yield PENDING. Neither status schedules a retry in foundation. Run validation explicitly after convergence. The future bounded orchestration design in ARCHITECTURE.md does not deliberately fail installation, install a permanent service or repeat active tests.

Repeated installation copies files to explicit relative destinations within src, controls, baselines and tools, removes obsolete files only from those managed folders, and reapplies restricted permissions. ProgramData history is outside the payload and preserved. The source module is unloaded before importing the installed manifest; validation executes in that installed module's session, with ModuleBase checked. Source and destination cannot overlap. Run installers serially: deployment copying is not a transactional upgrade and must not race another installation or assessment. A failed copy returns execution failure and can be retried; no rollback is claimed.

Validate actual packaging, detection/retry cadence, compliance ingestion, ACL access, signing and exit-code behavior in your tenant. No .intunewin is produced automatically; Microsoft packaging tooling and tenant deployment are separate operational steps.

Sources: [Microsoft discovery script requirements](https://learn.microsoft.com/en-us/intune/device-security/compliance/create-custom-script), [Microsoft compliance JSON rules](https://learn.microsoft.com/en-us/intune/device-security/compliance/create-custom-json).
