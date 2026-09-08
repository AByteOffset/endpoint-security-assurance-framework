# Milestone 2 validation report

## Already verified foundation

43 foundation Pester tests passed previously. The project owner reports successful real Windows 11 MDE lab validation of all five controls, overall PASS, ProgramData ACLs limited to SYSTEM/Administrators FullControl, and valid compressed Custom Compliance JSON. These are user-reported live results, not new live tests performed by this agent. They validate foundation 0.1.0, not the new Intune deployment path.

## Newly verified

- Complete Windows PowerShell 5.1 suite: 75 passed, 0 failed/skipped/inconclusive.
- Existing foundation tests retained and updated to produce complete 0.1.1 fixtures for the stricter shared result contract.
- Staging and SHA-256 verification, repeatable paths/hashes, tamper/unlisted/traversal rejection and safe staging cleanup.
- Installer exit separation under mocked boundaries: completed FAIL/PENDING returns 0; runtime failure returns nonzero. Idempotent temporary payload copying and actual installed-module reload remain covered.
- Cross-process mutex contention times out and later acquisition succeeds after release. Framework failure releases ownership. Temporary JSON validation failure preserves the old destination and removes the temporary artifact.
- Detection accepts completed PASS/FAIL/PENDING, rejects old engine or baseline requirements, validates full registry consistency and never ages out a certificate.
- Compliance preserves PASS/FAIL/REVIEW/PENDING, validates structure/counters/observations and fails closed on malformed state or unsafe ACLs. Pilot rules require only overall PASS.
- Uninstall runs against isolated filesystem fixtures, preserves history by default, removes only ESAF data on explicit purge, and preserves neighboring Defender/Intune sentinels. Registry and machine paths are substituted only in tests.
- Installation verification performs read-only inspection. Production AST scan rejects prohibited Defender/firewall/service-changing commands. Source review found no endpoint credentials or arbitrary data-driven commands.

Staging was built in a non-synced local directory because this workspace's OneDrive ancestry is a reparse path. No Content Prep Tool path was supplied; no .intunewin was generated. Bootstrap/hash manifests provide corruption detection, not cryptographic authenticity. Signature/release trust remains organizational. CI runs this same suite plus the production security scan; consult the Milestone 2 PR checks for the actual remote run result.

## Not yet verified

- Successful 0.1.1 installation after the process-only launch correction.
- Successful completion of .intunewin installation through Intune Management Extension.
- Actual Custom Compliance portal per-setting result.
- Production rollout, ARM64, or broad endpoint compatibility.

No Intune groups/apps/assignments/policies were created or changed by this development correction. No new security controls, Graph integration, active tests, remediation or permanent service were added. Engine is 0.1.1; Corporate-W11 baseline stays 1.0.0. Stop at the manual ONE-device pilot described in INTUNE_PILOT_GUIDE.md.

## User-reported one-device pilot failure

Intune assigned and downloaded the package, detection correctly reported 0.1.1 absent, and IME launched native 64-bit PowerShell as SYSTEM. Installation exited 1 before Program Files/ESAF was created. Existing ProgramData/ESAF and registry results are old 0.1.0 evidence. The VM reports all persistent execution-policy scopes Undefined and effective Windows PowerShell policy Restricted. The unsigned launcher omitted a process-only override. Install guidance and the uninstall wrapper now include -ExecutionPolicy Bypass without persistent policy writes. Three regression checks cover exact documented install commands, the uninstall invocation, and absence of persistent policy-changing code. A live retry remains necessary; successful deployment is not claimed.

## User-reported package version 2 diagnostics

The corrected process-only launcher still exits 1 under SYSTEM before Program Files/ESAF exists. The owner reports the exact IME-extracted package passes manifest validation, single-module import, path checks, directory checks, temporary payload copy with restricted ACLs, and execution-lock acquire/release. These isolate the remaining failure but do not identify its cause. Embedded bootstrap diagnostics now record each installer stage and sanitized failure metadata. Six new tests cover stages, sanitized records, ACL intent, isolated persistence and logging failure; existing installer success/failure coverage remains. ACL persistence tests substitute privileged ACL inspection and do not claim a new live SYSTEM run.

## Package-root resolution correction

The owner reports protected SYSTEM diagnostics identified package support loading as the failing stage, with ParameterBindingValidationException at the Join-Path call. PackageRoot now has no parameter default. The script body resolves an omitted argument from PSScriptRoot, rejects explicitly empty/whitespace values, and normalizes the path before architecture/package checks. The new package root resolution stage and its reviewed safe error message retain existing protected logging and exit behavior. Four added tests cover the parameter AST, omitted root from a different working directory, explicit alternate root, and empty/whitespace rejection in Windows PowerShell 5.1 child processes. Existing installer success/failure tests remain. A rebuilt package and live SYSTEM retry are still required to establish deployment success; engine 0.1.1, baseline 1.0.0, detection and the Intune launch command are unchanged.
