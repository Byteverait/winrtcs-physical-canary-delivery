# Read-only WinRTCS install status. Does not install, repair, remove, or start a task.
$ErrorActionPreference = 'Continue'
$root = 'C:\ProgramData\WinRTCS'
function Section([string]$Name) { Write-Output ('----- ' + $Name + ' -----') }
function Tail([string]$Path, [int]$Count) {
    if (-not (Test-Path -LiteralPath $Path)) { Write-Output ('ABSENT ' + $Path); return }
    $item = Get-Item -LiteralPath $Path
    Write-Output ('PATH=' + $Path + ' BYTES=' + $item.Length)
    $lines = [IO.File]::ReadAllLines($Path)
    $start = 0
    if ($lines.Length -gt $Count) { $start = $lines.Length - $Count }
    for ($i = $start; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]
        if ($line -match '(?i)token=|sig=|BEGIN ') { $line = 'REDACTED' }
        Write-Output $line
    }
}
function Show-Acl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { Write-Output ('ACL_ABSENT ' + $Path); return }
    $lines = @(& icacls.exe $Path 2>&1 | ForEach-Object { "$_" })
    $limit = 6
    if ($lines.Count -lt $limit) { $limit = $lines.Count }
    for ($i = 0; $i -lt $limit; $i++) { Write-Output $lines[$i] }
}
function Show-Events([string]$Log, [int[]]$Ids, [string]$Needle) {
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Ids; StartTime = (Get-Date).AddHours(-12) } -MaxEvents 40 -ErrorAction Stop)
        $shown = 0
        foreach ($event in $events) {
            $text = [string]$event.Message
            if ($Needle -and $text -notlike ('*' + $Needle + '*') -and $text -notlike '*powershell.exe*') { continue }
            if ($text.Length -gt 280) { $text = $text.Substring(0, 280) }
            $text = $text -replace '[\r\n]+', ' '
            if ($text -match '(?i)token=|sig=|BEGIN ') { $text = 'REDACTED' }
            Write-Output ('EVENT ' + $event.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') + ' ID=' + $event.Id + ' ' + $text)
            $shown++
            if ($shown -ge 6) { break }
        }
        if ($shown -eq 0) { Write-Output ('EVENT_NONE ' + $Log) }
    } catch {
        Write-Output ('EVENT_LOG_UNAVAILABLE ' + $Log)
    }
}
Section 'IDENTITY'
Write-Output ('COLLECTED_AT=' + [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
Write-Output ('USER=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
Section 'LOG'
Tail (Join-Path $root 'canary-install.log') 40
Tail 'C:\Windows\Temp\winrtcs-canary-diagnostic.log' 20
Section 'HANDOFF'
Tail (Join-Path $root 'canary-handoff.txt') 20
$runFile = Join-Path $root 'canary-run.id'
if (Test-Path -LiteralPath $runFile) { Write-Output ('RUN_FILE=' + ([IO.File]::ReadAllText($runFile)).Trim()) } else { Write-Output 'RUN_FILE=ABSENT' }
Section 'TASK'
foreach ($name in @('WinRTCSCanaryInstall', 'WinRTCSCanaryResume', '\Microsoft\Windows\WinRTCS\Agent', '\Microsoft\Windows\WinRTCS\Continuity')) {
    Write-Output ('QUERY ' + $name)
    & schtasks.exe /Query /TN $name /V /FO LIST 2>&1 | Select-String -Pattern 'TaskName|Status|Last Run Time|Last Result|Task To Run|Run As User|Scheduled Task State' | ForEach-Object { $_.Line }
}
try {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $task = $service.GetFolder('\').GetTask('WinRTCSCanaryInstall')
    $code = [int]$task.LastTaskResult
    Write-Output ('TASK_LAST_RESULT=' + $code)
    $unsigned = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$code), 0)
    Write-Output ('TASK_NTSTATUS=' + ('{0:X8}' -f $unsigned))
    Write-Output ('TASK_STATE_CODE=' + [int]$task.State)
} catch {
    Write-Output 'TASK_COM=ABSENT'
}
Section 'FILES'
foreach ($path in @(
    'C:\Windows\Temp\winrtcs_canary_unattended.ps1',
    'C:\ProgramData\WinRTCS\winrtcs_canary_unattended.ps1',
    'C:\Windows\Temp\winrtcs_canary_launcher.ps1',
    'C:\ProgramData\WinRTCS\winrtcs_canary_launcher.ps1'
)) {
    if (Test-Path -LiteralPath $path) {
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Output ($path + ' BYTES=' + (Get-Item -LiteralPath $path).Length + ' SHA256=' + $hash)
        Show-Acl $path
    } else { Write-Output ('ABSENT ' + $path) }
}
Section 'GENERATION'
$places = New-Object System.Collections.Generic.List[string]
[void]$places.Add($root)
[void]$places.Add('C:\ProgramData\Microsoft\WinRTCS\cache')
foreach ($parent in @($root, 'C:\Windows\Temp')) {
    if (-not (Test-Path -LiteralPath $parent)) { continue }
    $dirs = @(Get-ChildItem -LiteralPath $parent -Directory -Filter 'winrtcs-canary-*' -ErrorAction SilentlyContinue | Select-Object -First 3)
    foreach ($dir in $dirs) { [void]$places.Add($dir.FullName) }
}
foreach ($place in $places) {
    Write-Output ('PLACE ' + $place)
    if (-not (Test-Path -LiteralPath $place)) { Write-Output 'ABSENT'; continue }
    foreach ($name in @('winrtcs.version', 'winrtcs_keeper.ps1', 'winrtcs_continuity.ps1', 'winrtcs_watchdog.cmd')) {
        $path = Join-Path $place $name
        if (Test-Path -LiteralPath $path) {
            $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            Write-Output ($name + ' BYTES=' + (Get-Item -LiteralPath $path).Length + ' SHA256=' + $hash)
        } else { Write-Output ($name + '=ABSENT') }
    }
}
Section 'EVENTS'
Show-Events 'Microsoft-Windows-TaskScheduler/Operational' @(101, 103, 201, 203) 'WinRTCSCanaryInstall'
Show-Events 'Application' @(1000) 'powershell.exe'
Show-Events 'Application' @(1001) 'powershell.exe'
Show-Events 'Microsoft-Windows-CodeIntegrity/Operational' @(3033, 3076, 3077) 'powershell.exe'
Show-Events 'Microsoft-Windows-AppLocker/EXE and DLL' @(8003, 8004) 'powershell.exe'
Section 'KEEPER'
Tail (Join-Path $root 'keeper-status.txt') 40
Tail (Join-Path $root 'keeper-audit.log') 20
Section 'SERVICES'
foreach ($fp in @('41b1cb0dd5f78b27', '1432e226cdbd6e78')) {
    $svc = 'ScreenConnect Client (' + $fp + ')'
    Write-Output ('SERVICE ' + $svc)
    & sc.exe qc $svc 2>&1 | Select-String -Pattern 'SERVICE_NAME|BINARY_PATH_NAME|STATE' | ForEach-Object { $_.Line }
    & sc.exe query $svc 2>&1 | Select-String -Pattern 'STATE' | ForEach-Object { $_.Line }
}
Section 'OTHER_SCREENCONNECT'
& sc.exe query type= service state= all 2>&1 | Select-String -Pattern 'SCREENCONNECT' | ForEach-Object { $_.Line }
Section 'MSI'
Get-ChildItem -LiteralPath $root -Filter 'install.log' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 4 | ForEach-Object { Tail $_.FullName 15 }
Section 'REBOOT'
$reboot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
Write-Output ('REBOOT_REQUIRED_KEY=' + (Test-Path -LiteralPath $reboot))
$ops = Get-ChildItem -LiteralPath $root -Filter 'keeper-op-*.txt' -ErrorAction SilentlyContinue
foreach ($op in $ops) { Tail $op.FullName 8 }
Section 'END'
Write-Output 'STATUS_COLLECTOR=READ_ONLY'
