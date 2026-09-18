# Milestone 5 support evidence and Intune diagnostics retrieval

## Purpose and boundary

Milestone 5 is installed runtime behavior in engine 0.3.0. It produces a compact support artifact after ESAF has successfully finalized canonical evidence. The artifact helps an authorized operator inspect normalized assurance state and can be retrieved on demand through Microsoft Intune Collect Diagnostics. It is a derivative transport record, not a replacement for ESAF evidence, a compliance signal, continuous telemetry, cryptographic attestation or a custom backend.

Canonical full-fidelity evidence remains authoritative at:

```text
C:\ProgramData\ESAF\history\<runId>\evidence.json
```

The exporter writes the latest sanitized derivative to:

```text
C:\ProgramData\ESAF\support\latest-assurance.json
```

When the existing Intune Management Extension Logs directory is available, it also writes the same serialized bytes to this optional transport location:

```text
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ESAF-Assurance.log
```

The IME location is only a transport adapter. ESAF does not create missing Microsoft directories, start or restart IME, change Intune configuration, store endpoint cloud credentials or use Microsoft Graph. Microsoft diagnostic collection behavior is an external dependency and is outside the canonical ESAF evidence contract.

## Transport contract 0.1

The exporter accepts only canonical JSON with `schemaVersion` exactly `1.0`, a non-empty `runId`, a non-empty `device`, and a `controls` array. It rejects malformed input, unsupported schemas and duplicate control IDs. It does not modify the source file.

The top-level transport fields are exactly:

- `transportVersion` (`0.1`)
- `evidenceSchemaVersion` (`1.0`)
- `device`
- `runId`
- `exportedAtUtc`
- `sourceEvidenceSha256`
- `controls`

Each control contains only:

- `id`
- `evidenceProvider`
- `observed`
- `collectedAt`
- `status`

The artifact excludes raw provider evidence, uncontrolled provider exception text, registry dumps, tenant identifiers, UPNs, Graph data, authorization headers, tokens, secrets and credentials. An error remains visible only through its normalized status.

`sourceEvidenceSha256` is SHA-256 over the exact bytes of the canonical history `evidence.json` used for the export. It supports source linkage and an integrity comparison between known copies. It does not prove origin, cryptographic authenticity or hardware-backed attestation. A local administrator can replace the source and derivative artifacts and remains outside the local ACL trust boundary.

## Publication and failure behavior

`Invoke-ESAFValidation` invokes the exporter only after `Write-ESAFReport` has completed canonical history/latest JSON, log and registry publication. If canonical publication fails, no new support export is attempted. Both derivative destinations use a temporary file, validate the complete JSON, verify the written content and atomically move or replace the final file. The IME copy is serialized once with the canonical support copy so successful outputs are byte-equivalent. Fixed filenames replace the previous latest derivative and do not append indefinitely; canonical per-run history remains unchanged.

The support directory uses the existing ESAF storage protection routine: inheritance is disabled and only SYSTEM and BUILTIN\Administrators receive FullControl. The exporter does not alter ACLs or grant permissions in the Microsoft-owned IME Logs directory. Failure to produce the canonical support derivative is reported separately and does not change the completed endpoint verdict. `latest-assurance.json` therefore means the last successfully exported support artifact, not necessarily the most recent completed assessment. If run B completes but its export fails, a valid artifact from run A remains with its original `runId` and `exportedAtUtc`; ESAF does not delete or mislabel it. A missing IME directory records the optional adapter as unavailable; an adapter copy failure is likewise separate and does not fail the assessment.

## Generic live validation procedure

Use an approved Windows 11 lab endpoint with ESAF installed and, for the adapter check, Intune Management Extension already present. Do not use production identifiers in tracked fixtures or documentation.

1. From elevated 64-bit Windows PowerShell 5.1, invoke a normal read-only ESAF validation and record its Run ID and verdict.
2. Confirm the matching canonical history `evidence.json` exists and that `support\latest-assurance.json` contains transport version `0.1`, evidence schema version `1.0`, the same device and Run ID, and only the documented fields.
3. Compute SHA-256 over the exact canonical history evidence file and compare it with `sourceEvidenceSha256`.
4. If IME Logs exists, confirm `ESAF-Assurance.log` exists and its file bytes are identical to `support\latest-assurance.json`. If IME Logs does not exist, confirm ESAF did not create it and that the canonical support artifact still exists.
5. In Intune, request **Collect diagnostics** for the approved lab device. After collection completes, retrieve `ESAF-Assurance.log` from the diagnostic bundle.
6. Compare SHA-256 of the retrieved transport file with the endpoint transport file, parse the JSON, and confirm the field allowlists. Check explicitly that raw evidence, exception text, tenant/UPN data, Graph data, authorization values, tokens and credentials are absent.
7. Compare normalized observations with the canonical source and retain the Run ID/hash association in the validation record. Never treat matching hashes as proof against a privileged local attacker.

The manual proof of concept confirmed generically that Intune Collect Diagnostics retrieved a sanitized transport artifact byte-for-byte, the JSON parsed, normalized endpoint observations were present, and prohibited raw/identity/credential fields were absent. That result validates an on-demand retrieval path for one lab workflow; it does not establish fleet coverage or a guaranteed Microsoft service contract.

## Current limitations

- Retrieval is operator-initiated and subject to Microsoft Intune diagnostic collection availability, timing, packaging and retention behavior.
- The artifact contains only the latest derivative; canonical ESAF history holds prior assessments.
- No push channel, continuous telemetry, custom service, database or central evidence repository is included.
- No signature, MAC, TPM quote, hardware-backed attestation or independent authenticity proof is included.
- Local SYSTEM/Administrators can read or forge locally stored evidence.
- The adapter does not imply that Intune has evaluated the ESAF content. Custom Compliance behavior remains unchanged.
- Transport contract `0.1` is separate from unchanged ESAF evidence schema `1.0`.
