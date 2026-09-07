# Intune deployment and recertification

Pilot on an approved lab endpoint first. Use Microsoft Win32 Content Prep Tool to package the repository content (exclude .git, .tools, artifacts and tests), preserving src, controls, baselines, tools and intune/package. See [packaging](../packaging/README.md). Deploy as a required Win32 application with SYSTEM install behavior and a Windows 11 requirement. There is no service, scheduled task, Graph credential or policy modification.

Install command from a 32-bit Intune launch context:

```text
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File .\intune\package\Install-ESAF.ps1
```

From a 64-bit lab shell use powershell.exe normally. Apply the organization's signing policy. Installation copies the endpoint payload to Program Files/ESAF, restricts its ACL, imports the installed module and runs validation. Output remains ProgramData/ESAF with restricted ACLs. A successful report with PASS, FAIL, REVIEW or PENDING returns installation exit code **0**. Failed copy, invalid input, platform discovery or report/registry publication returns **1**. Security FAIL is never mapped to an installation failure.

Upload Detect-ESAF.ps1 as a custom detection script with 32-bit execution on 64-bit clients **No**. It emits a nonempty success string and exit 0 only when installed module/baseline versions, completed validation versions, status, registry Run ID and 7-day freshness match. It accepts security FAIL as installed. Missing, malformed, old, version-mismatched or incomplete publication produces exit 1 without stdout.

For baseline 1.1.0, publish a revised package and detection script with RequiredBaselineVersion=1.1.0. Similarly update RequiredEngineVersion after an engine/test change. A 0.1.0/1.0.0 certificate fails the revised detection even if installed files were copied earlier. Intune's next required-app evaluation reruns installation/validation. Exact version equality prevents accidental certification against a different baseline. Freshness defaults to 168 hours: once stale, required-app reevaluation invokes validation again. This is Intune-driven, not a guaranteed on-device schedule. Align assignment cadence and compliance grace periods; immediate manual recertification is available through the runner.

Upload Compliance-Discovery.ps1 as a Windows Custom Compliance discovery script. Run as logged-on user **No**, run in 64-bit PowerShell **Yes**. Configure signature enforcement according to your signed deployment. Upload Compliance-Rules.json and assign the policy to the same pilot group. Discovery performs no security collection and emits one compressed JSON line. SYSTEM access is necessary because results are intentionally not readable by ordinary users.

Rules require ESAFStatus/MDEAssurance/DefenderAssurance/NetworkAssurance PASS and exact baseline/engine versions. Missing, stale, unsupported-version or inconsistent results return PENDING and cannot satisfy the rules. Non-PASS group results report REVIEW. Intune compliance is binary; ESAF's richer verdict remains in local data and ESAFStatus. Update both discovery's version contract and rules operands with package/detection versions for each release. Replace the generic support URL in rules with an approved organization help page if desired.

Validate actual packaging, detection/retry cadence, compliance ingestion, ACL access, signing and exit-code behavior in your tenant. No .intunewin is produced automatically; Microsoft packaging tooling and tenant deployment are separate operational steps.

Sources: [Microsoft discovery script requirements](https://learn.microsoft.com/en-us/intune/device-security/compliance/create-custom-script), [Microsoft compliance JSON rules](https://learn.microsoft.com/en-us/intune/device-security/compliance/create-custom-json).
