# One WinRTCS-owned staging action. It does not install, reboot, or start a shell.
param(
    [string]$Root = 'C:\ProgramData\WinRTCS\recovery'
)
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'YAFA-HP') {
    Write-Output 'SCOPE_REFUSED=NOT_YAFA_HP'
    exit 2
}
if ($Root -ne 'C:\ProgramData\WinRTCS\recovery') {
    Write-Output 'SCOPE_REFUSED=ROOT'
    exit 2
}
$stop = Join-Path $Root 'emergency.stop'
$relative = 'probe.txt'
$destination = Join-Path $Root $relative
$backup = $destination + '.bak'
$auditPath = Join-Path $Root 'audit.txt'
New-Item -ItemType Directory -Force -Path $Root | Out-Null
function Write-Audit([string]$Result) {
    $line = ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) + ' ACTION=stage_verified_bytes RESULT=' + $Result
    [IO.File]::AppendAllText($auditPath, ($line + "`r`n"))
    Write-Output $line
}
if (Test-Path -LiteralPath $stop) {
    Write-Audit 'EMERGENCY_STOP'
    Write-Output 'RECOVERY_EXECUTED=false'
    exit 0
}
$payload = [Text.Encoding]::UTF8.GetBytes('winrtcs-recovery-probe')
$sha = [Security.Cryptography.SHA256]::Create()
try { $expected = ([BitConverter]::ToString($sha.ComputeHash($payload))).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
function Get-FileSha([string]$Path) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $hasher.Dispose() }
}
if ((Test-Path -LiteralPath $destination) -and (Get-FileSha $destination) -eq $expected) {
    Write-Audit 'IDEMPOTENT'
} else {
    $previous = $null
    if (Test-Path -LiteralPath $destination) { $previous = [IO.File]::ReadAllBytes($destination) }
    $temporary = $destination + '.tmp'
    [IO.File]::WriteAllBytes($temporary, $payload)
    if ($previous -ne $null) { [IO.File]::WriteAllBytes($backup, $previous) }
    [IO.File]::Copy($temporary, $destination, $true)
    Remove-Item -LiteralPath $temporary -Force
    $readback = Get-FileSha $destination
    if ($readback -ne $expected) {
        if ($previous -eq $null) { Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue }
        else { [IO.File]::WriteAllBytes($destination, $previous) }
        Write-Audit 'POSTCONDITION'
        Write-Output 'RECOVERY_EXECUTED=false'
        exit 3
    }
    Write-Audit 'STAGED'
    Write-Output ('STAGED_SHA256=' + $readback)
}
if ((Test-Path -LiteralPath $destination) -and (Get-FileSha $destination) -eq $expected) {
    Write-Audit 'IDEMPOTENT'
} else {
    Write-Audit 'POSTCONDITION'
    exit 3
}
if (Test-Path -LiteralPath $backup) {
    [IO.File]::Copy($backup, $destination, $true)
    Remove-Item -LiteralPath $backup -Force
    Write-Audit 'ROLLED_BACK'
} elseif (Test-Path -LiteralPath $destination) {
    Remove-Item -LiteralPath $destination -Force
    if (Test-Path -LiteralPath $destination) {
        Write-Audit 'POSTCONDITION'
        exit 3
    }
    Write-Audit 'ROLLED_BACK'
}
Write-Output 'RECOVERY_EXECUTED=true'
Write-Output 'RECOVERY_MODE=stage_verified_bytes'
Write-Output 'KEEPER=NOT_CALLED'
Write-Output 'REBOOT=NOT_CALLED'
exit 0
