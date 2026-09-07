# Security model

ESAF is a privileged local assessor, not an independent attestation authority. SYSTEM/Administrators can alter the engine, baseline, registry or result and can forge assurance. A compromised kernel or administrator is outside the protection supplied by local ACLs. Intune results must not be described as cryptographic attestation.

| Threat | Defense and remaining limitation |
| --- | --- |
| Malicious control JSON / command injection | Strict fields, canonical IDs, internal provider allow-list and validated expected-state domains; never evaluate control data as PowerShell. Trusted source code itself executes as administrator. |
| Compromised baseline | Privileged install directory, versioned review and tests. No baseline signature verification in foundation; trusted packaging and change review are required. |
| Tampered/stale result | SYSTEM/Administrators-only protected ACLs and Administrators ownership on existing storage, run/version matching and required control completeness. Age is exposed separately as CertificationFreshness; no freshness rule is enforced by default. Local admins can still forge both. |
| Privilege abuse / path redirection | No remediation operations. Reject existing reparse points in output/install paths, protect directory ACLs, serialize writers. Initial trusted deployment and uncompromised local admin are prerequisites. |
| Credential leakage | No endpoint cloud identity or credential configuration. Providers retain only selected security-state fields. Exception text is replaced with fixed safe messages. |
| Unsafe active tests | No active or Deep test executor. Functional definitions must declare false. Future tests require explicit approval, isolation and independent safety review. |
| Artifact persistence | No canaries in this release. JSON temporary files have finally cleanup; the lock handle is disposed. Interrupted runs can leave partial history, which is never certification by itself. |
| Replay / partial publication | Latest result is checked against registry run ID/version/status. Substantially future timestamps are rejected; stale observations remain historical verdicts with a separate freshness attribute. Administrators must explicitly adopt any freshness compliance requirement. Privileged replay remains possible. |
| Availability / storage exhaustion | Collection errors do not stop other providers. Publication errors fail execution. History/log retention and collection command timeouts are future work; operators monitor storage and use Intune execution limits. |

The runner writes only ESAF-owned files/ACLs and HKLM SOFTWARE/ESAF. It never disables Defender, Tamper Protection or firewall, changes ASR/policies, creates exclusions, runs malware/EICAR/Atomic tests or stores Graph credentials. Result/evidence contain the hostname and security posture, so access is limited to SYSTEM and local Administrators. Use organizational code signing and trusted Win32 packaging before broad deployment.

Standard users have no access to result/evidence/history because no current consumer requires it. SYSTEM-based Intune discovery retains FullControl; Administrators retain FullControl. Protected directory rules inherit to new children. Existing children have explicit grants replaced and ownership assigned to Administrators, closing the prior-owner DACL rewrite gap. No result signing is attempted; local administrators inherently remain outside this trust boundary. See LIVE_LAB_CHECKLIST.md for actual ACL and standard-user denial checks, which unit ACL construction does not replace.

Standard remains read-only for security controls. Future harmless canaries require deterministic cleanup. Deep mode is not implemented. No third-party source code is incorporated into the core; development Pester dependencies are excluded from commits.
