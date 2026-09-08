# Milestone 2 validation report

## Already verified foundation

43 foundation Pester tests passed previously. The project owner reports successful real Windows 11 MDE lab validation of all five controls, overall PASS, ProgramData ACLs limited to SYSTEM/Administrators FullControl, and valid compressed Custom Compliance JSON. These are user-reported live results, not new live tests performed by this agent. They validate foundation 0.1.0, not the new Intune deployment path.

## Newly verified

- Complete Windows PowerShell 5.1 suite: 62 passed, 0 failed/skipped/inconclusive.
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

- Real Intune installation in SYSTEM context.
- Actual .intunewin execution through Intune Management Extension.
- Actual Custom Compliance portal per-setting result.
- Production rollout, ARM64, or broad endpoint compatibility.

No Intune groups/apps/assignments/policies were created or changed. No new security controls, Graph integration, active tests, remediation or permanent service were added. Engine is 0.1.1; Corporate-W11 baseline stays 1.0.0. Stop at the manual ONE-device pilot described in INTUNE_PILOT_GUIDE.md.
