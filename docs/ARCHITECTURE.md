# Architecture

`src/ESAF.psm1` loads the module components. `Core` orchestrates; `Controls` validates baseline/control data and applicability; `Evidence` performs approved read-only collection; `Verdict` compares normalized values and aggregates; `Reporting` publishes artifacts; `Utility` supplies platform detection, safe JSON reads and random IDs. `tools/Invoke-ESAF.ps1` alone formats human console output.

Intune deploys files under Program Files and starts validation as SYSTEM in a 64-bit process. The runner loads all definitions before collection, detects Windows client/build applicability and generates a 128-bit random Run ID with .NET RandomNumberGenerator. All timestamps are UTC ISO-8601. Each applicable control collects only an allowlisted subset of local data. Provider errors are sanitized structured records; other controls continue.

Outputs under `C:\ProgramData\ESAF` are `result.json`, `evidence.json`, `ESAF.log`, `history/<RunID>/result.json` and `history/<RunID>/evidence.json`. An exclusive `run.lock` file handle prevents concurrent publication; the small unlocked file remains between runs. Temporary JSON files are removed in finally blocks. History uses immutable unique run directories. There is no automatic retention deletion yet; operations must monitor disk usage and archive approved history.

Latest JSON files are individually replaced atomically. There is no cross-file transaction: history is written first, then evidence, then result, log and registry. Registry publication is the last successful execution step. Consumers require matching Run IDs and versions; a partial publication cannot be reported as a current successful install. Detailed evidence is never stored in the registry. Disk/registry/platform/input failures terminate execution; security provider errors are control results.

The eight registry fields are EngineVersion, BaselineName, BaselineVersion, LastRun, LastRunId, Status, CriticalFailures and HighFailures. Intune discovery reads only result.json and this summary. A future central verifier can correlate the Run ID without distributing cloud identities to endpoints. See [future cloud design](../cloud-verifier/README.md).
