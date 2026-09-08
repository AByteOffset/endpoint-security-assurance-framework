function Enter-ESAFExecutionLock {
    param([ValidateRange(0,600)][int]$TimeoutSeconds=30)
    $security=New-Object Security.AccessControl.MutexSecurity
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity=New-Object Security.Principal.SecurityIdentifier($sid)
        $security.AddAccessRule((New-Object Security.AccessControl.MutexAccessRule($identity,'FullControl','Allow')))
    }
    $created=$false
    $mutex=New-Object Threading.Mutex($false,'Global\ESAF.Execution.v1',[ref]$created,$security)
    try {
        try { $acquired=$mutex.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds)) }
        catch [Threading.AbandonedMutexException] { $acquired=$true }
        if (-not $acquired) { throw 'ESAF execution lock timed out.' }
        $mutex
    } catch { $mutex.Dispose(); throw }
}

function Exit-ESAFExecutionLock {
    param($Lock)
    if ($null -ne $Lock) {
        try { $Lock.ReleaseMutex() } finally { $Lock.Dispose() }
    }
}
