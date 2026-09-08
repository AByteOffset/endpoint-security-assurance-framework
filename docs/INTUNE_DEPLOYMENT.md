# Deployment contract - engine 0.1.1

Use [INTUNE_PILOT_GUIDE.md](INTUNE_PILOT_GUIDE.md) for the exact one-device workflow. No tenant changes are automated.

Build staging first: source-tree direct installer execution is intentionally unsupported. The installer validates manifest/hashes before importing payload code, acquires the shared execution mutex, copies production files to Program Files/ESAF, preserves ProgramData history and invokes the installed module. Engine 0.1.1 is a patch for material deployment/locking/result-consumer changes. Corporate-W11 remains 1.0.0 because desired security state is unchanged.

Exit 0 means completed framework execution and publication, including security PASS, REVIEW, FAIL or PENDING. Installation, integrity, lock, runtime and publication errors return 1. Registry publication is the final commit marker. JSON files are individually atomically replaced; there is no two-file transaction. Consumers reject mismatched result/registry state. History retains unique runs.

Detection uses the installed protected ResultContract helper, requires exact installed/certified engine and baseline versions and verifies all eight registry summary fields. Age never triggers reinstall. Compliance uses the same strict helper, checks result ACLs, and emits eight compact string fields. Only ESAFStatus=PASS is enforced for this pilot; categories and freshness are diagnostic. The 168-hour freshness label never triggers automatic recertification.

Uninstall coordinates on the same mutex, removes the fixed Program Files/ESAF directory and ESAF summary, and preserves evidence by default. Explicit -Purge removes ProgramData/ESAF too. Remove compliance and Required assignments before rollback. The CMD wrapper resolves native PowerShell without relying on environment expansion in Intune's uninstall field.

SYSTEM is the intended install context; elevated administrator lab execution alone does not prove it. No new controls, active tests, services, cloud identity or remediation are added. PENDING/REVIEW requires explicit subsequent validation; the future bounded orchestration design remains unimplemented.

The pilot currently uses unsigned PowerShell scripts. `-ExecutionPolicy Bypass` applies only to the launched PowerShell process and does not persistently alter endpoint execution policy. ESAF does not call Set-ExecutionPolicy, modify LocalMachine/CurrentUser policy, create execution-policy registry values, or weaken system/GPO policy. Production should prefer signed release scripts and normal organizational script-control policy.

Exact Intune install command:

```text
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-ESAF.ps1
```

Uninstall-ESAF.cmd selects native 64-bit Windows PowerShell and invokes `"%ESAF_PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Uninstall-ESAF.ps1"`.
