# Foundation validation report

Validated on 2026-09-07 using 64-bit Windows PowerShell 5.1 and Pester 5.6.1.

- 28 Pester tests passed; zero failures, skips or inconclusive tests.
- All 15 PowerShell source/manifest files parsed; all 7 tracked JSON files parsed. The shipped baseline and five controls passed semantic validation, and the module imported successfully.
- Mocked full validation generated matching result/evidence Run IDs, history across successive runs, operational log and registry-summary calls. Repeat publication exercised atomic JSON replacement on .NET Framework.
- Compliance discovery emitted a single compressed JSON object; malformed, missing, stale, incomplete and inconsistent fixtures failed closed.
- Version-aware detection rejected newer required engine/baseline versions and stale/incomplete results. A current completed security FAIL remained successfully detected.
- An isolated child-process installer fixture replaced privileged boundaries and verified exit 0 for completed security FAIL and exit 1 for execution exceptions.
- Git diff whitespace validation passed. Repository source scans found no embedded credentials, tokens, private keys, tenant IDs, personal email addresses or user-specific absolute paths. Review found no Defender/ASR/firewall policy mutations, exclusions or data-driven command execution. The Invoke-Expression string in a rejection test is inert malicious input, not executable code.

The initial local test process used a process-only execution-policy override because the developer machine blocks scripts by default. It did not change machine execution policy. Pester used temporary HKCU test registry space; actual ESAF security collection, HKLM summary writes and deployment ACL changes were mocked. Downloaded test dependencies and development-only GitHub tooling are ignored and excluded from the endpoint payload and Git commits.

The repository is private, default branch main, with implementation on feature/esaf-foundation and pull request 1 left open for review. GitHub refused main branch protection with HTTP 403: the account must upgrade to GitHub Pro or make the repository public. Privacy was preserved, so required PR/check enforcement and force-push protection could not be enabled. CI results are available on the PR's Checks tab.

Not claimed: real MDE/Defender integration, Intune tenant deployment, .intunewin packaging, signing, live ACL enforcement, active functional blocking, cloud telemetry or Deep tests. Those require the approved lab and release process described in TESTING.md. Local administrators remain able to forge local evidence; this is not cryptographic attestation. Collection timeouts and automatic history/log retention remain documented future work.
