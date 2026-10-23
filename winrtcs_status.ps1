# Read-only WinRTCS install status. Does not install, repair, or remove software.
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
Section 'IDENTITY'
Write-Output ('UTC=' + [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
Write-Output ('USER=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
Section 'LOG'
Tail (Join-Path $root 'canary-install.log') 40
Tail 'C:\Windows\Temp\winrtcs-canary-diagnostic.log' 20
Section 'TASK'
foreach ($name in @('WinRTCSCanaryInstall', 'WinRTCSCanaryResume', '\Microsoft\Windows\WinRTCS\Agent', '\Microsoft\Windows\WinRTCS\Continuity')) {
    Write-Output ('QUERY ' + $name)
    & schtasks.exe /Query /TN $name /V /FO LIST 2>&1 | Select-String -Pattern 'TaskName|Status|Last Run Time|Last Result|Task To Run|Run As User|Scheduled Task State' | ForEach-Object { $_.Line }
}
Section 'KEEPER'
Tail (Join-Path $root 'keeper-status.txt') 40
Tail (Join-Path $root 'keeper-audit.log') 20
Section 'GENERATION'
foreach ($name in @('winrtcs.version', 'winrtcs_keeper.ps1', 'winrtcs_continuity.ps1', 'winrtcs_watchdog.cmd')) {
    $path = Join-Path $root $name
    if (Test-Path -LiteralPath $path) {
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Output ($name + ' BYTES=' + (Get-Item -LiteralPath $path).Length + ' SHA256=' + $hash)
    } else { Write-Output ($name + '=ABSENT') }
}
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
