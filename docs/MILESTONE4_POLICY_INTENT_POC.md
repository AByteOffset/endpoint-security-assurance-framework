# Milestone 4: Microsoft policy intent reconciliation POC

## Purpose and boundary

This central, read-only proof of concept compares one native Microsoft policy setting with one existing ESAF endpoint observation. Microsoft owns policy intent and remains the management, configuration and reporting plane. ESAF independently observes selected effective Windows state. The POC reconciles those two records; it does not deploy policy, calculate complete effective policy, remediate an endpoint, change Intune compliance or replace Defender or Intune reporting.

The only production mapping is:

| Microsoft definition | Microsoft choice | Normalized intent | ESAF control | Evidence provider |
| --- | --- | --- | --- | --- |
| `device_vendor_msft_policy_config_defender_allowrealtimemonitoring` | matched definition option with `optionValue.value = 1` | `Enabled` | `ESAF-AV-002` | `RealTimeProtection` |
| same definition | matched definition option with `optionValue.value = 0` | `Disabled` | `ESAF-AV-002` | `RealTimeProtection` |

The configured `choiceSettingValue.value` must exactly match an `itemId` in the setting definition returned by Microsoft Graph. ESAF normalizes the matched option through its `optionValue.value`; it never infers intent from an item-ID suffix.

## Authentication and Graph reads

Run the POC centrally from an already authenticated Microsoft Graph PowerShell delegated session. It checks for these scopes:

- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `Device.Read.All`

No app registration, application credential, token persistence, endpoint Graph identity or write permission is used. The implementation calls `Invoke-MgGraphRequest` only with `-Method GET`.

The POC reads:

- `v1.0/deviceManagement/managedDevices` to resolve exactly one Intune device by the supplied name;
- `v1.0/devices` to correlate `azureADDeviceId` with the Entra device object;
- `v1.0/devices/{id}/transitiveMemberOf/microsoft.graph.group` for group IDs;
- `beta/deviceManagement/configurationPolicies/{id}`;
- the policy's beta `assignments` and `settings` relationships;
- `beta/deviceManagement/configurationSettings/{URL-encoded-settingDefinitionId}` for the complete Microsoft setting definition.

Microsoft documents the Intune configuration-policy and setting APIs used here under Microsoft Graph beta. Beta behavior can change and is not a permanent ESAF runtime contract. Capability and response-shape validation is required before any broader design.

References:

- [Get an Intune configuration policy](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfigv2-devicemanagementconfigurationpolicy-get?view=graph-rest-beta)
- [List configuration policy settings](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfigv2-devicemanagementconfigurationsetting-list?view=graph-rest-beta)
- [Get a configuration setting definition](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfigv2-devicemanagementconfigurationsettingdefinition-get?view=graph-rest-beta)
- [List Intune managed devices](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0)
- [List a device's transitive memberships](https://learn.microsoft.com/en-us/graph/api/device-list-transitivememberof?view=graph-rest-1.0)

## Identity and assignment decision

`-PolicyId`, `-DeviceName` and `-EvidencePath` are required. The policy is never selected by a similar-looking name. Device-name resolution must return exactly one Intune managed device. Zero or multiple matches return `ERROR`. Subsequent correlation uses the managed device's `azureADDeviceId`, not its hostname.

The supported assignment contract is intentionally narrow: every assignment must be a direct `#microsoft.graph.groupAssignmentTarget` with `deviceAndAppManagementAssignmentFilterType = none`, no filter ID and a group ID. The POC compares assigned group IDs with the resolved device's transitive group membership IDs.

Assignment filters, exclusions, missing filter declarations and all other targets return `UNKNOWN`. If supported group assignments exist but none match, the deterministic result is `UNKNOWN` with `assignment.applies = false`; this POC does not assert a broader not-applicable state.

## Evidence and reconciliation

The input must be an existing ESAF schema 1.0 `evidence.json` with top-level `schemaVersion`, `runId`, `device` and `controls`. Its device must match `-DeviceName`, and exactly one `ESAF-AV-002` must exist.

Reconciliation uses only `evidence.observed`. It does not emit or compare the raw provider payload.

- Equal known `Enabled` or `Disabled` values: `MATCH`.
- Unequal known values: `MISMATCH`.
- Missing, ambiguous, unsupported or non-collected intent/evidence, and unsupported assignments: `UNKNOWN`.
- Invalid schema or device identity, ambiguous managed-device resolution, Graph failure or runtime failure: `ERROR`.

These outcomes belong to reconciliation contract 0.1. They are not ESAF PASS/FAIL, do not change schema 1.0 and do not alter the endpoint's existing verdict.

The result object includes only the resolved device identifiers, selected policy metadata, assignment matches, normalized setting/probe values, outcome and a sanitized reason. It excludes tokens, authorization headers, Graph context, unrelated memberships, raw evidence and unrelated tenant data.

## Run and live validation

Install Microsoft Graph PowerShell centrally and authenticate interactively with the three delegated read scopes:

```powershell
Connect-MgGraph -Scopes @(
    'DeviceManagementConfiguration.Read.All'
    'DeviceManagementManagedDevices.Read.All'
    'Device.Read.All'
)
```

Copy the protected endpoint `evidence.json` through an approved administrative process to a central location outside this Git repository. Then run:

```powershell
.\policy-assurance\Invoke-ESAFPolicyReconciliation.ps1 `
    -PolicyId '<configuration-policy-guid>' `
    -DeviceName '<exact-intune-device-name>' `
    -EvidencePath 'C:\ApprovedValidationInput\evidence.json'
```

To persist only the sanitized reconciliation object, add an output path outside the repository:

```powershell
-OutputPath 'C:\ApprovedValidationOutput\reconciliation.json'
```

The parent directory must already exist. Repository output is refused by the production wrapper. Unit tests use an explicit Pester fixture path and synthetic IDs.

The owner previously performed a separate live manual validation of this one mapping and observed an assigned Microsoft `Enabled` intent matching an ESAF `Enabled` observation. Tenant, device, group and policy identifiers from that validation are intentionally absent from source, tests and documentation. CI uses mocks and never contacts the tenant.

## Limitations

This POC supports one setting, one ESAF probe and one assignment form. It does not claim fleet support, full policy-conflict resolution, complete effective-policy calculation, assignment-filter evaluation, exclusion evaluation, friendly group-name enrichment, MDE P2 functionality or production stability for beta APIs. It does not modify the endpoint package, engine 0.2.0, Corporate-W11 1.1.0, schema 1.0, detection, Custom Compliance or Conditional Access.
