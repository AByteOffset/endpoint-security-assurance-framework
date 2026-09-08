# Milestone 2: ONE-device Intune pilot

Foundation 0.1.0 live MDE/ACL/JSON success was reported by the project owner. This guide validates the new 0.1.1 SYSTEM deployment path. Development has made no tenant changes. Do not broaden deployment or add active tests.

## Preparation and assignment safety

Use an approved Windows 11 x64 MDE lab device enrolled in Intune, with appropriate licensing/admin access and an agreed recovery path. Create or use an assigned-membership device security group ESAF-Pilot-Windows containing ONLY that device. Verify no broad/nested membership. DO NOT assign to All Users or All Devices. Check existing Conditional Access/noncompliance consequences with the tenant owner before assigning the pilot compliance policy; do not change unrelated policies.

## A. Build the package

From a clean reviewed checkout in 64-bit Windows PowerShell 5.1, using organizational signing/execution policy. For the approved unsigned pilot on a Restricted host, first launch that shell with `powershell.exe -NoProfile -ExecutionPolicy Bypass`; never change persistent policy:

```powershell
git fetch origin
git switch feature/intune-pilot-deployment
git pull --ff-only
Install-Module Pester -RequiredVersion 5.6.1 -Scope CurrentUser -Force -SkipPublisherCheck
.\tools\Test-ESAF.ps1
$build=.\packaging\Build-ESAFPackage.ps1 -OutputRoot C:\ESAFBuild
$build | Format-List
. .\packaging\PackageSupport.ps1
Assert-ESAFPackage $build.stagingPath | Select-Object engineVersion,baseline,buildTime
```

Use a local non-synced output path; reparse points are rejected. Only the recognized ESAF-Package child is cleaned. Staging contains Install-ESAF.ps1, Detect-ESAF.ps1, Uninstall-ESAF.ps1, Uninstall-ESAF.cmd, PackageSupport.ps1, ExecutionLock.ps1, package-manifest.json and payload/{src,controls,baselines,tools}. An explicit runtime allow-list excludes tests, workflows, development tools, credentials, lab output and third-party binaries. SHA-256 covers every staged file except the manifest itself. Paths and payload hashes repeat deterministically; UTC build time changes. Hashes detect corruption, not malicious replacement of both manifest and bootstrap scripts. Trust comes from reviewed release/signing and Intune distribution. For production signed releases, sign source before staging; editing staged files after hashing invalidates the package.

Obtain Microsoft's Content Prep Tool through your approved process, OUTSIDE staging. ESAF never downloads it. With an already approved local tool:

```powershell
& 'C:\ApprovedTools\IntuneWinAppUtil.exe' -c 'C:\ESAFBuild\ESAF-Package' -s 'Install-ESAF.ps1' -o 'C:\ESAFBuild\intunewin' -q
Get-Item C:\ESAFBuild\intunewin\Install-ESAF.intunewin
```

Alternatively supply `-ContentPrepToolPath C:\ApprovedTools\IntuneWinAppUtil.exe` to the builder. Without that parameter only staging is generated. See [Microsoft package preparation](https://learn.microsoft.com/en-us/intune/app-management/deployment/create-win32-package).

## B. Create the Win32 app manually

Current Microsoft guidance uses Intune admin center > Apps > All Apps > Create, then Windows app (Win32). Some tenant UIs use Add; labels may vary by rollout. Select Install-ESAF.intunewin.

| Setting | Pilot value |
| --- | --- |
| Name | ESAF 0.1.1 - One-device pilot |
| Publisher | Approved internal publisher / ESAF |
| Description | Read-only endpoint assurance; security verdict is separate from app install |
| Installer type | Command line |
| Install behavior | System |
| Installation time | 15 minutes; investigate timeout before changing |
| Device restart behavior | Determine behavior based on return codes; ESAF emits no reboot codes |
| Return codes | 0 Success; 1 Failed |
| Architecture | x64; ARM64 is not validated in this pilot |
| Minimum OS | Applicable supported Windows 11 entry |
| Dependencies/supersedence | None |
| Assignments | Required, ESAF-Pilot-Windows ONLY |
| Available uninstall | No; administrator-managed rollback |

Install command:

```text
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-ESAF.ps1
```

Intune command-line execution can launch 32-bit PowerShell when called by name. Sysnative selects 64-bit Windows PowerShell from that context. The installer rejects 32-bit execution. In an already 64-bit manual shell use powershell.exe/System32; Sysnative is visible to 32-bit callers.

The pilot currently uses unsigned PowerShell scripts. `-ExecutionPolicy Bypass` applies only to the launched PowerShell process and does not persistently alter endpoint execution policy. ESAF never calls Set-ExecutionPolicy, modifies LocalMachine/CurrentUser policy, or creates execution-policy registry values. Group Policy and organizational script controls remain authoritative; do not weaken them. Production should prefer signed release scripts and normal organizational script-control policy.

Uninstall command:

```text
Uninstall-ESAF.cmd
```

The wrapper chooses Sysnative when available, otherwise System32, then invokes `"%ESAF_PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Uninstall-ESAF.ps1"`. It avoids relying on environment variable expansion in Intune's uninstall field.

Detection: Use a custom detection script, upload staged Detect-ESAF.ps1, set Run script as 32-bit process on 64-bit clients = No. For this approved unsigned pilot, set Enforce script signature check = No; production signed releases should follow organizational signature policy. Detection uses the installed protected ResultContract helper and requires engine 0.1.1, Corporate-W11 1.0.0, complete result and matching registry summary. Exit 0 with stdout means installed. Completed PASS/REVIEW/FAIL/PENDING all qualify; elapsed age never triggers reinstallation. Missing files or inconsistent versions/state are not detected.

Review final assignments and count ONE device before saving. Do not assign compliance until app installation and local verification succeed. [Microsoft Win32 configuration](https://learn.microsoft.com/en-us/intune/app-management/deployment/add-win32).

## C. Verify SYSTEM installation

Preferred option A: let Intune perform the required SYSTEM installation. Sync only the approved device through the normal Intune/Company Portal workflow and allow IME check-in. Inspect app Device install status and the device's managed-app detail. Record time, return status and Run ID. Troubleshooting logs are under C:\ProgramData\Microsoft\IntuneManagementExtension\Logs. Security FAIL is not an installation defect.

Elevated read-only device inspection:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Program Files\ESAF\tools\Test-ESAFInstallation.ps1'
Get-Content C:\ProgramData\ESAF\result.json -Raw | ConvertFrom-Json
Get-ItemProperty HKLM:\SOFTWARE\ESAF
```

For actual SYSTEM verification, run Test-ESAFSystemContext.ps1 through an explicitly approved Intune SYSTEM script assignment to the same group (logged-on credentials No, 64-bit host Yes). It checks identity and existing installation; it never elevates itself or reruns validation. Administrator execution reports SystemContext=False and proves no SYSTEM behavior.

Option B, lab only, with already approved administrator-provided PsExec:

```powershell
& 'C:\ApprovedTools\PsExec64.exe' -s C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Program Files\ESAF\tools\Test-ESAFSystemContext.ps1'
```

Do not download/bundle PsExec through ESAF. Its temporary service/EULA behavior requires separate organizational approval. ESAF creates no permanent service. Actual Intune deployment remains preferred.

## D. Add Custom Compliance manually

After app verification, go to Devices > Compliance policies > Scripts (some UIs group this under Devices > Compliance). Add a Windows discovery script and upload intune/compliance/Compliance-Discovery.ps1. Use logged-on credentials No, 64-bit PowerShell host Yes, and signature checking disabled for the approved unsigned pilot; production should follow organizational signature policy.

Create a Windows 10 and later compliance policy (this platform includes Windows 11), enable Custom Compliance, choose the uploaded discovery script, and upload intune/compliance/Compliance-Rules.json. Review the displayed rule: ESAFStatus String IsEquals PASS. Assign ONLY ESAF-Pilot-Windows. Do not add category/freshness enforcement for this first pilot. Use the tenant owner's approved noncompliance action/grace configuration and account for existing Conditional Access consequences.

The lightweight adapter reads the installed helper, result, ACLs and registry; it never invokes validation. Output includes ESAFStatus, MDEAssurance, DefenderAssurance, NetworkAssurance, BaselineVersion, EngineVersion, CertificationFreshness and CertificationRunId. Invalid schema, incomplete or inconsistent results, registry mismatch and unsafe result permissions fail closed. Only PASS satisfies the pilot rule. End-user text directs users to IT without exposing internal evidence.

Discovery normally runs on an eight-hour cycle; Check Compliance can run existing discovery, while a push does not guarantee immediate reevaluation. Allow check-in time and distinguish app installation from custom compliance evaluation. Inspect device/policy per-setting details and Reports > Device compliance > Reports > Noncompliant devices and settings; filter the pilot platform/device and generate the report. Record ESAFStatus, timestamp and local Run ID. UI wording can vary. [Discovery configuration](https://learn.microsoft.com/en-us/intune/device-security/compliance/create-custom-script), [evaluation/reporting](https://learn.microsoft.com/en-us/intune/device-security/compliance/custom-settings).

## E. Acceptance and rollback

Capture app installation success under SYSTEM, installed versions, matching result/evidence/history Run ID, registry, restricted ACLs, discovery JSON and actual portal per-setting status. An explicit rerun must preserve old history and avoid nested program directories. FAIL-to-exit-0 is tested with mocks; never weaken protection to manufacture a failure. PENDING/REVIEW requires an explicit later run after convergence; no automatic retries are installed.

Rollback order: remove pilot compliance assignment, remove Required app assignment, then assign Uninstall only to the same group or run the administrator command below. Verify no remaining Required assignment can reinstall ESAF. Do not change Defender, MDE, Intune or unrelated policies.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Program Files\ESAF\tools\Uninstall-ESAF.ps1'
```

Default uninstall removes Program Files/ESAF and HKLM SOFTWARE/ESAF, preserving all ProgramData evidence/history. Detection becomes false and discovery becomes PENDING until unassigned. Explicitly approved `-Purge` on the staged uninstall script also removes ProgramData/ESAF. Repeated staged uninstall is safe. Keep the external staged package for rollback because installed uninstall removes itself with the program directory.

Stop at this one-device pilot. Wider assignments require owner review of actual IME/SYSTEM and compliance evidence.

After this launch correction, rebuild staging and the .intunewin package so the updated uninstall wrapper and manifest are included. Update the existing one-device app install command and retry only the approved device. Old 0.1.0 ProgramData and registry artifacts do not prove 0.1.1 installation. Confirm Program Files/ESAF, installed version and a new matching Run ID before assigning compliance.
