# Refresh local service facts. It does not start, stop, or install anything.
$ErrorActionPreference = 'Stop'
$allowed = @('YOSSI-2018', 'YAFA-HP', 'WARCO')
if ($allowed -notcontains $env:COMPUTERNAME) {
    Write-Output 'SCOPE_REFUSED=NOT_OBSERVATION_HOST'
    exit 2
}
$names = @(
    'ScreenConnect Client (41b1cb0dd5f78b27)',
    'ScreenConnect Client (1432e226cdbd6e78)'
)
$root = 'C:\ProgramData\WinRTCS\recovery'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$path = Join-Path $root 'service-observation.txt'
$lines = New-Object System.Collections.Generic.List[string]
[void]$lines.Add('observed_at=' + [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
[void]$lines.Add('computer=' + $env:COMPUTERNAME)
foreach ($name in $names) {
    $query = & sc.exe query $name 2>&1 | Out-String
    $state = 'ABSENT'
    if ($query -match 'STATE\s+:\s+4\s+RUNNING') { $state = 'RUNNING' }
    elseif ($query -match 'STATE\s+:\s+1\s+STOPPED') { $state = 'STOPPED' }
    [void]$lines.Add('service=' + $name + ' state=' + $state)
    Write-Output ('SERVICE=' + $name + ' STATE=' + $state)
}
$keeper = 'C:\ProgramData\WinRTCS\keeper-status.txt'
if (Test-Path -LiteralPath $keeper) {
    foreach ($line in [IO.File]::ReadAllLines($keeper)) {
        if ($line.StartsWith('backup_local_health=') -or $line.StartsWith('backup_last_error=') -or $line.StartsWith('KEEPER_HEALTH=')) {
            [void]$lines.Add('keeper_file_' + $line)
            Write-Output ('KEEPER_FILE_' + $line)
        }
    }
    $written = (Get-Item -LiteralPath $keeper).LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    [void]$lines.Add('keeper_file_written=' + $written)
    Write-Output ('KEEPER_FILE_WRITTEN=' + $written)
}
[IO.File]::WriteAllLines($path, $lines)
Write-Output 'OBSERVATION_WRITTEN=true'
Write-Output 'SERVICE_RESTART=NOT_CALLED'
Write-Output 'KEEPER=NOT_CALLED'
Write-Output 'REBOOT=NOT_CALLED'
exit 0
