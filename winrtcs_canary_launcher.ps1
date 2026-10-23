# WinRTCS physical canary. Signature and component hashes are checked before any local install.
# Local installation does not enroll the device. Backend identity stays NOT_ENROLLED.
# UPDATE_V2_INCLUDED=false
# CANARY_UNATTENDED=1
param(
    [switch]$Continue,
    [switch]$PostReboot,
    [switch]$HandoffProbe,
    [switch]$ProvenanceSelfTest,
    [switch]$RebootPolicyCheck,
    [string]$RebootPolicy = 'NEVER',
    [string]$StagePath = '',
    [string]$ExpectedSha256 = '',
    [string]$SourceUrl = '',
    [string]$RunId = ''
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::CheckCertificateRevocationList = $true
[Net.ServicePointManager]::Expect100Continue = $false
$SoftwareBase = 'https://raw.githubusercontent.com/Byteverait/winrtcs-physical-canary-delivery/main'
$script:RebootPolicy = 'NEVER'
$ExpectedBootstrap = '0a62d34817f218df4cdf17f48b6d56ac767131843614842360551c7ab58880b7'
$script:CanaryLog = 'C:\ProgramData\WinRTCS\canary-install.log'
$script:CanaryRoot = 'C:\ProgramData\WinRTCS'

function Protect-CanaryText([string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $safe = [regex]::Replace($Text, '(?i)(token|sig)=[^\s]+', '${1}=REDACTED')
    $safe = [regex]::Replace($safe, '(?i)-----BEGIN [A-Z0-9 ]+-----', 'BEGIN REDACTED')
    $safe = [regex]::Replace($safe, '[\r\n]+', ' ')
    if ($safe.Length -gt 180) { $safe = $safe.Substring(0, 180) }
    return $safe
}
function Get-CanaryErrorText($Record) {
    $current = $null
    if ($null -ne $Record) { $current = $Record.Exception }
    $names = New-Object System.Collections.Generic.List[string]
    $status = ''
    $message = ''
    while ($null -ne $current) {
        [void]$names.Add($current.GetType().Name)
        if (-not $status -and $current -is [Net.WebException]) { $status = [string]$current.Status }
        if (-not $message -and $current.Message) { $message = [string]$current.Message }
        $current = $current.InnerException
    }
    $chain = ''
    if ($names.Count -gt 0) { $chain = ($names -join '/') }
    return [pscustomobject]@{ Chain = $chain; Status = $status; Message = (Protect-CanaryText $message) }
}
function Write-CanaryLog([string]$Line) {
    $safe = [regex]::Replace($Line, '(?i)(token|sig)=[^\s]+', '${1}=REDACTED')
    $safe = [regex]::Replace($safe, '(?i)-----BEGIN [A-Z0-9 ]+-----', 'BEGIN REDACTED')
    if ($safe -match '(?i)(token|sig)=(?!REDACTED)') { return }
    if ($safe -match '(?i)BEGIN (?!REDACTED)') { return }
    $stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $text = $stamp + ' ' + $safe + "`r`n"
    foreach ($path in @($script:CanaryLog, 'C:\Windows\Temp\winrtcs-canary-diagnostic.log')) {
        try { [IO.File]::AppendAllText($path, $text) } catch { }
    }
}
function Emit([string]$Line) {
    Write-Output $Line
    Write-CanaryLog $Line
    if ($Line -eq 'WINRTCS_PHYSICAL_CANARY=FAIL') {
        Write-Output 'STATE=FAILED'
        Write-CanaryLog 'STATE=FAILED'
    } elseif ($Line -eq 'WINRTCS_PHYSICAL_CANARY=PASS' -or $Line -eq 'WINRTCS_PHYSICAL_CANARY=ALREADY_INSTALLED') {
        Write-Output 'STATE=SUCCEEDED'
        Write-CanaryLog 'STATE=SUCCEEDED'
    }
}
function Initialize-CanaryLog {
    $script:CanaryRootCreated = -not (Test-Path -LiteralPath $script:CanaryRoot)
    if ($script:CanaryRootCreated) {
        New-Item -ItemType Directory -Path $script:CanaryRoot | Out-Null
    }
    if (-not (Test-Path -LiteralPath $script:CanaryLog)) {
        [IO.File]::WriteAllText($script:CanaryLog, '')
    }
}
function Protect-CanaryLog {
    if ($script:CanaryRootCreated) {
        & icacls.exe $script:CanaryRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
    }
    $reader = '*' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value + ':(R)'
    & icacls.exe $script:CanaryLog /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' $reader | Out-Null
}
function Format-TaskResult($Code) {
    if ($null -eq $Code -or [string]$Code -eq '') { return 'UNKNOWN' }
    $signed = 0
    if (-not [int]::TryParse([string]$Code, [ref]$signed)) { return 'UNKNOWN' }
    $unsigned = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$signed), 0)
    return ('{0:X8}' -f $unsigned)
}
function Write-Handoff([string]$Line) {
    $path = Join-Path $script:CanaryRoot 'canary-handoff.txt'
    $safe = Protect-CanaryText $Line
    if ($safe -match '(?i)(token|sig)=(?!REDACTED)') { return }
    $stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $created = -not (Test-Path -LiteralPath $path)
    [IO.File]::AppendAllText($path, ($stamp + ' ' + $safe + "`r`n"))
    Write-CanaryLog $Line
    if ($created) {
        & icacls.exe $path /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    }
}
function Test-WorkerEntered([string]$RunId) {
    $path = Join-Path $script:CanaryRoot 'canary-handoff.txt'
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    $needle = 'WORKER_ENTERED=true RUN_ID=' + $RunId
    foreach ($line in [IO.File]::ReadAllLines($path)) {
        if ($line.Contains($needle)) { return $true }
    }
    return $false
}
function Get-CanaryTask([string]$Name) {
    $found = [pscustomobject]@{ Absent = $true; State = ''; LastResult = ''; LastRun = ''; Action = '' }
    try {
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $task = $service.GetFolder('\').GetTask($Name)
        $found.Absent = $false
        $taskState = [int]$task.State
        if ($taskState -eq 4) { $found.State = 'Running' }
        elseif ($taskState -eq 2) { $found.State = 'Queued' }
        elseif ($taskState -eq 3) { $found.State = 'Ready' }
        elseif ($taskState -eq 1) { $found.State = 'Disabled' }
        else { $found.State = 'Unknown' }
        $found.LastResult = [string]([int]$task.LastTaskResult)
        try {
            $ran = [datetime]$task.LastRunTime
            if ($ran.Year -ge 2000) { $found.LastRun = $ran.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        } catch { }
        try {
            foreach ($item in @($task.Definition.Actions)) {
                $found.Action = ([string]$item.Path + ' ' + [string]$item.Arguments).Trim()
                break
            }
        } catch { }
    } catch {
        $found.Absent = $true
        $found.State = ''
    }
    return $found
}
function Get-Sha256File([string]$Path) {
    $last = $null
    for ($try = 1; $try -le 3; $try++) {
        $hasher = $null
        $stream = $null
        try {
            $hasher = [Security.Cryptography.SHA256]::Create()
            $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            return ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } catch {
            $last = $_
            if ($try -ge 3) { throw }
            Start-Sleep -Seconds $try
        } finally {
            if ($null -ne $stream) { $stream.Dispose() }
            if ($null -ne $hasher) { $hasher.Dispose() }
        }
    }
    throw $last
}
function Write-RunProvenance([string]$Id, [hashtable]$Fields) {
    if ($Id -notmatch '^[0-9a-f]{32}$') { return }
    $dir = Join-Path $script:CanaryRoot ('runs\' + $Id)
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        & icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
    }
    $path = Join-Path $dir 'provenance.txt'
    $current = @{}
    if (Test-Path -LiteralPath $path) {
        foreach ($line in [IO.File]::ReadAllLines($path)) {
            $pair = $line.Split('=', 2)
            if ($pair.Length -eq 2) { $current[$pair[0]] = $pair[1] }
        }
    }
    foreach ($key in @($Fields.Keys)) { $current[[string]$key] = [string]$Fields[$key] }
    $names = @(
        'run_id','stage','source_url','expected_sha256','candidate_path','candidate_sha256',
        'foreground_path','foreground_sha256','worker_path','worker_sha256','generation_sha256','reboot_policy'
    )
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($name in $names) {
        $value = ''
        if ($current.ContainsKey($name)) { $value = [string]$current[$name] }
        $value = Protect-CanaryText $value
        [void]$lines.Add($name + '=' + $value)
    }
    $temp = $path + '.tmp'
    [IO.File]::WriteAllText($temp, (($lines.ToArray() -join "`r`n") + "`r`n"))
    [IO.File]::Copy($temp, $path, $true)
    Remove-Item -LiteralPath $temp -Force
    & icacls.exe $path /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    $stage = [string]$current['stage']
    if ($stage -eq 'EXECUTED_FOREGROUND' -or $stage -eq 'REGISTERED_WORKER' -or $stage -eq 'RUNNING_WORKER' -or $stage -eq 'COMMITTED_GENERATION') {
        $pointer = Join-Path $script:CanaryRoot 'runs\current.txt'
        $pointerTemp = $pointer + '.tmp'
        $parent = Split-Path -Parent $pointer
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
        [IO.File]::WriteAllText($pointerTemp, ('run_id=' + $Id + "`r`n"))
        [IO.File]::Copy($pointerTemp, $pointer, $true)
        Remove-Item -LiteralPath $pointerTemp -Force
        & icacls.exe $pointer /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    }
}
function Confirm-LauncherIdentity {
    $actual = Get-Sha256File $PSCommandPath
    Emit ('EXECUTED_PATH=' + $PSCommandPath)
    Emit ('EXECUTED_SHA256=' + $actual)
    $expected = ([string]$ExpectedSha256).Trim().ToLowerInvariant()
    if ($expected -and $expected -notmatch '^[0-9a-f]{64}$') {
        Emit 'FAILURE_CODE=LAUNCHER_IDENTITY'
        Emit 'IDENTITY_REASON=EXPECTED_HASH_MALFORMED'
        Emit 'STATE=FAILED'
        exit 3
    }
    if ($Continue) {
        $id = ([string]$RunId).Trim().ToLowerInvariant()
        if ($id -notmatch '^[0-9a-f]{32}$') {
            $runFile = Join-Path $script:CanaryRoot 'canary-run.id'
            if (Test-Path -LiteralPath $runFile) { $id = ([IO.File]::ReadAllText($runFile)).Trim().ToLowerInvariant() }
        }
        $record = Join-Path $script:CanaryRoot ('runs\' + $id + '\provenance.txt')
        $recorded = ''
        if (Test-Path -LiteralPath $record) {
            foreach ($line in [IO.File]::ReadAllLines($record)) {
                if ($line.StartsWith('foreground_sha256=')) { $recorded = $line.Substring(19).Trim().ToLowerInvariant() }
            }
        }
        if ($recorded -ne $actual -or -not $recorded) {
            Emit 'FAILURE_CODE=LAUNCHER_IDENTITY'
            Emit ('EXPECTED_SHA256=' + $recorded)
            Emit ('ACTUAL_SHA256=' + $actual)
            Emit 'STATE=FAILED'
            exit 3
        }
        Emit 'LAUNCHER_IDENTITY=MATCH'
        return
    }
    if (-not $expected) {
        Emit 'FAILURE_CODE=LAUNCHER_IDENTITY_ABSENT'
        Emit 'STATE=FAILED'
        exit 3
    }
    $id = ([string]$RunId).Trim().ToLowerInvariant()
    if ($id -notmatch '^[0-9a-f]{32}$') { $id = [guid]::NewGuid().ToString('n') }
    if ($expected -ne $actual) {
        Write-RunProvenance $id @{
            run_id = $id
            stage = 'IDENTITY_MISMATCH'
            source_url = [string]$SourceUrl
            expected_sha256 = $expected
            foreground_path = $PSCommandPath
            foreground_sha256 = $actual
        }
        Emit 'FAILURE_CODE=LAUNCHER_IDENTITY'
        Emit ('EXPECTED_SHA256=' + $expected)
        Emit ('ACTUAL_SHA256=' + $actual)
        Emit ('RUN_ID=' + $id)
        Emit 'PROVENANCE_STAGE=IDENTITY_MISMATCH'
        Emit 'KEEPER=NOT_CALLED'
        Emit 'REBOOT=NOT_CALLED'
        Emit 'STATE=FAILED'
        exit 3
    }
    Emit 'LAUNCHER_IDENTITY=MATCH'
    if ($SourceUrl) { Emit ('SOURCE_URL=' + (Protect-CanaryText $SourceUrl)) }
    if ($ProvenanceSelfTest) {
        Write-RunProvenance $id @{
            run_id = $id
            stage = 'VERIFIED_CANDIDATE'
            source_url = [string]$SourceUrl
            expected_sha256 = $expected
            candidate_path = $PSCommandPath
            candidate_sha256 = $actual
            foreground_path = ''
            foreground_sha256 = ''
            worker_path = ''
            worker_sha256 = ''
            generation_sha256 = ''
            reboot_policy = ''
        }
        Emit ('RUN_ID=' + $id)
        Emit 'PROVENANCE_STAGE=VERIFIED_CANDIDATE'
        Emit 'INSTALL_RUNTIME=NOT_ACTIVE'
        Emit 'KEEPER=NOT_CALLED'
        Emit 'REBOOT=NOT_CALLED'
        Emit 'TASK_CREATED=false'
        Emit 'STATE=SUCCEEDED'
        exit 0
    }
}
function Receive-File([string]$Name, [string]$Dest) {
    $urls = @(
        ($SoftwareBase + '/' + $Name),
        ('https://github.com/Byteverait/winrtcs-physical-canary-delivery/raw/main/' + $Name)
    )
    foreach ($url in $urls) {
        for ($try = 1; $try -le 3; $try++) {
            $client = $null
            try {
                if (Test-Path -LiteralPath $Dest) { Remove-Item -LiteralPath $Dest -Force }
                $client = New-Object Net.WebClient
                $client.Headers['User-Agent'] = 'winrtcs-canary-delivery'
                $client.DownloadFile($url, $Dest)
                if ((Test-Path -LiteralPath $Dest) -and ((Get-Item -LiteralPath $Dest).Length -gt 0)) { return }
            } catch {
                if ($try -lt 3) { Start-Sleep -Seconds (2 * $try) }
            } finally {
                if ($null -ne $client) { $client.Dispose() }
            }
        }
    }
    Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Emit 'STATE=FAILED'
    Emit 'FAILURE_CODE=DOWNLOAD'
    exit 3
}
function Test-ServiceRunning([string]$Name) {
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & sc.exe query $Name 2>&1 | Out-String
    $ErrorActionPreference = $preference
    return $out -match 'STATE\s+:\s+4\s+RUNNING'
}
function Register-CanaryReboot([string]$Enroll) {
    $launcherCopy = Join-Path $script:CanaryRoot 'winrtcs_canary_launcher.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $launcherCopy -Force
    & icacls.exe $launcherCopy /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    $taskArgs = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $launcherCopy + '" -PostReboot'
    $xmlArgs = $taskArgs.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    $xmlPath = Join-Path $script:CanaryRoot 'canary-reboot.xml'
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author"><Exec>
    <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
    <Arguments>$xmlArgs</Arguments>
  </Exec></Actions>
</Task>
"@
    $utf16 = New-Object System.Text.UnicodeEncoding $false, $true
    [IO.File]::WriteAllText($xmlPath, $xml, $utf16)
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & schtasks.exe /Create /TN 'WinRTCSCanaryResume' /XML $xmlPath /F 2>&1 | Out-Null
    $createCode = $LASTEXITCODE
    if ($createCode -eq 0) {
        & schtasks.exe /Delete /TN 'WinRTCSBootstrapResume' /F 2>&1 | Out-Null
    }
    $ErrorActionPreference = $preference
    Remove-Item -LiteralPath $xmlPath -Force -ErrorAction SilentlyContinue
    if ($createCode -ne 0) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=REBOOT_TASK'
        exit 4
    }
    if ($Enroll -and (Test-Path -LiteralPath $Enroll)) { Remove-Item -LiteralPath $Enroll -Force }
    Emit 'STATE=IN_PROGRESS'
    Emit ('REBOOT_POLICY=' + $script:RebootPolicy)
    Emit 'REBOOT_REQUIRED=true'
    if ($script:RebootPolicy -ne 'ON_REQUIRED') {
        $await = Join-Path $script:CanaryRoot 'reboot-awaiting.txt'
        [IO.File]::WriteAllText($await, ("REBOOT_POLICY=NEVER`r`nREBOOT_STATE=AWAITING_REBOOT`r`n"))
        & icacls.exe $await /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
        Emit 'REBOOT_STATE=AWAITING_REBOOT'
        Emit 'REBOOT=NOT_CALLED'
        Emit 'SHUTDOWN=NOT_CALLED'
        Emit 'OVERALL_STATE=PARTIAL'
        Emit 'HEALTH=AWAITING_REBOOT'
        exit 0
    }
    & shutdown.exe /r /t 0 /f | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=REBOOT_START'
        exit 4
    }
    exit 0
}
function Invoke-PostReboot {
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & schtasks.exe /Delete /TN 'WinRTCSCanaryResume' /F 2>&1 | Out-Null
    $ErrorActionPreference = 'Stop'
    Emit 'STATE=IN_PROGRESS'
    $keeper = Join-Path $script:CanaryRoot 'winrtcs_keeper.ps1'
    $continuity = Join-Path $script:CanaryRoot 'winrtcs_continuity.ps1'
    $version = 'C:\ProgramData\Microsoft\WinRTCS\cache\winrtcs.version'
    if (-not (Test-Path -LiteralPath $keeper) -or -not (Test-Path -LiteralPath $continuity) -or -not (Test-Path -LiteralPath $version)) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=REBOOT_RESUME_MISSING'
        exit 4
    }
    $ErrorActionPreference = 'Continue'
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $keeper -Action Ensure
    $keeperCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($keeperCode -ne 0) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=KEEPER_ENSURE'
        Emit ('INSTALL_EXIT=' + $keeperCode)
        exit 4
    }
    $keeperMap = @{}
    $keeperStatus = Join-Path $script:CanaryRoot 'keeper-status.txt'
    if (Test-Path -LiteralPath $keeperStatus) {
        foreach ($line in [IO.File]::ReadAllLines($keeperStatus)) {
            $pair = $line.Split('=', 2)
            if ($pair.Length -eq 2) { $keeperMap[$pair[0].Trim()] = $pair[1].Trim() }
        }
    }
    if ([string]$keeperMap['KEEPER_INSTALL_REBOOT_REQUIRED'] -eq 'true') {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=REBOOT_LOOP'
        exit 4
    }
    if ([string]$keeperMap['KEEPER_HEALTH'] -ne 'HEALTHY') {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=KEEPER_NOT_HEALTHY'
        exit 4
    }
    $ErrorActionPreference = 'Continue'
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $continuity -Action Prepare
    $prepare = $LASTEXITCODE
    $watchExit = -1
    if ($prepare -eq 0) {
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $continuity -Action Watch | Out-Null
        $watchExit = $LASTEXITCODE
    }
    $ErrorActionPreference = 'Stop'
    if ($prepare -ne 0) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=TASK_CREATE'
        exit 4
    }
    $pulsv = Test-ServiceRunning 'ScreenConnect Client (41b1cb0dd5f78b27)'
    $seczio = Test-ServiceRunning 'ScreenConnect Client (1432e226cdbd6e78)'
    if (-not $pulsv -or -not $seczio) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=GUEST_SERVICE_NOT_RUNNING'
        exit 4
    }
    $generation = Get-Sha256File $version
    Emit ('GENERATION=' + $generation)
    Publish-InstallSplit 'SUCCEEDED' $keeperMap $watchExit
    exit 0
}

function Invoke-HandoffProbe {
    if ($env:COMPUTERNAME -ne 'YAFA-HP') {
        Emit 'SCOPE_REFUSED=NOT_YAFA_HP'
        exit 2
    }
    $rebootKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    if (Test-Path -LiteralPath $rebootKey) {
        Emit 'FAILURE_CODE=REBOOT_BLOCKED'
        Emit 'STATE=IN_PROGRESS'
        exit 3
    }
    $active = Get-CanaryTask 'WinRTCSCanaryInstall'
    if (-not $active.Absent -and $active.State -eq 'Running') {
        Emit 'HANDOFF=ALREADY_ACTIVE'
        Emit 'STATE=IN_PROGRESS'
        exit 0
    }
    $dir = Join-Path $script:CanaryRoot 'handoff'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $worker = Join-Path $dir 'probe-worker.ps1'
    $marker = Join-Path $dir 'probe-marker.txt'
    Set-Content -LiteralPath $worker -Encoding ASCII -Value @(
        "Set-Content -LiteralPath '$marker' -Value 'WORKER_ENTERED' -Encoding ASCII"
        'exit 0'
    )
    $taskArgs = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $worker + '"'
    $xmlArgs = $taskArgs.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    $xmlPath = Join-Path $dir 'probe-task.xml'
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT15M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author"><Exec>
    <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
    <Arguments>$xmlArgs</Arguments>
  </Exec></Actions>
</Task>
"@
    $utf16 = New-Object System.Text.UnicodeEncoding $false, $true
    [IO.File]::WriteAllText($xmlPath, $xml, $utf16)
    & schtasks.exe /Create /TN 'WinRTCSCanaryHandoffProbe' /XML $xmlPath /F | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Emit 'FAILURE_CODE=PROBE_TASK'
        exit 4
    }
    & schtasks.exe /Run /TN 'WinRTCSCanaryHandoffProbe' | Out-Null
    $runCode = $LASTEXITCODE
    Emit ('SCHTASKS_RUN=' + $runCode)
    if ($runCode -ne 0) {
        Emit 'FAILURE_CODE=PROBE_NOT_DISPATCHED'
        Emit 'STATE=IN_PROGRESS'
        exit 4
    }
    $seen = $false
    for ($wait = 0; $wait -lt 30; $wait++) {
        if (Test-Path -LiteralPath $marker) { $seen = $true; break }
        Start-Sleep -Seconds 1
    }
    $probeTask = Get-CanaryTask 'WinRTCSCanaryHandoffProbe'
    Emit 'PROBE=HANDOFF_ONLY'
    Emit 'KEEPER=NOT_CALLED'
    Emit 'REBOOT=NOT_CALLED'
    Emit ('PROBE_WORKER=' + $worker)
    Emit ('TASK_SCHEDULER_STATE=' + $probeTask.State)
    Emit ('TASK_EXIT_CODE=' + $probeTask.LastResult)
    if ($seen) {
        Emit 'HANDOFF=WORKER_ENTERED'
        Emit 'STATE=IN_PROGRESS'
        exit 0
    }
    if ([string]$probeTask.LastResult -eq '-1073741502') {
        Emit 'FAILURE_CODE=TASK_STARTUP'
        Emit 'FAULTING_MODULE=UNKNOWN'
        Emit 'STATE=FAILED'
        exit 4
    }
    Emit 'HANDOFF=WORKER_NOT_ENTERED'
    Emit 'STATE=IN_PROGRESS'
    exit 0
}
Initialize-CanaryLog
Emit 'LAUNCHER_STARTED=true'
Emit 'LOG=C:\ProgramData\WinRTCS\canary-install.log'
if ($null -ne [Net.ServicePointManager]::ServerCertificateValidationCallback) {
    Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Emit 'FAILURE_CODE=TLS_CALLBACK'
    exit 2
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Emit 'FAILURE_CODE=ADMINISTRATOR_REQUIRED'
    exit 1
}
Confirm-LauncherIdentity
$script:RebootPolicy = ([string]$RebootPolicy).Trim().ToUpperInvariant()
if ($script:RebootPolicy -ne 'NEVER' -and $script:RebootPolicy -ne 'ON_REQUIRED') {
    Emit 'FAILURE_CODE=REBOOT_POLICY'
    Emit 'REBOOT=NOT_CALLED'
    Emit 'STATE=FAILED'
    exit 3
}
Emit ('REBOOT_POLICY=' + $script:RebootPolicy)
if ($RebootPolicyCheck) {
    if ($script:RebootPolicy -ne 'NEVER') {
        Emit 'FAILURE_CODE=REBOOT_POLICY'
        Emit 'REBOOT=NOT_CALLED'
        Emit 'SHUTDOWN=NOT_CALLED'
        exit 3
    }
    Emit 'REBOOT_STATE=SUPPRESSED'
    Emit 'REBOOT=NOT_CALLED'
    Emit 'SHUTDOWN=NOT_CALLED'
    Emit 'KEEPER=NOT_CALLED'
    Emit 'TASK_CREATED=false'
    Emit 'STATE=SUCCEEDED'
    exit 0
}
if ($HandoffProbe) {
    if ($script:RebootPolicy -ne 'NEVER') {
        Emit 'FAILURE_CODE=REBOOT_POLICY'
        Emit 'REBOOT=NOT_CALLED'
        exit 3
    }
    Invoke-HandoffProbe
}
Protect-CanaryLog
Emit 'STATE=IN_PROGRESS'
if ($PostReboot) {
    Invoke-PostReboot
}
$installed = (Test-ServiceRunning 'ScreenConnect Client (41b1cb0dd5f78b27)') -and (Test-ServiceRunning 'ScreenConnect Client (1432e226cdbd6e78)') -and (Test-Path -LiteralPath 'C:\ProgramData\WinRTCS\winrtcs_device_client.ps1')
if ($installed -and -not $Continue) {
    Emit 'LOCAL_INSTALL_OBSERVED=true'
    Emit 'PULSV=RUNNING'
    Emit 'SECZIO=RUNNING'
}
$installTask = Get-CanaryTask 'WinRTCSCanaryInstall'
$canaryResume = Get-CanaryTask 'WinRTCSCanaryResume'
if (-not $Continue -and ((-not $installTask.Absent -and $installTask.State -eq 'Running') -or (-not $canaryResume.Absent -and $canaryResume.State -eq 'Running'))) {
    Emit 'STATE=IN_PROGRESS'
    exit 0
}
$resumeFile = Join-Path $script:CanaryRoot 'bootstrap-resume.txt'
if (-not $Continue -and (Test-Path -LiteralPath $resumeFile) -and ([IO.File]::ReadAllText($resumeFile) -match 'PHASE=POST_KEEPER')) {
    if ($canaryResume.Absent) { Register-CanaryReboot '' }
    Emit 'STATE=IN_PROGRESS'
    Emit 'REBOOT_REQUIRED=true'
    exit 0
}
$resume = Get-CanaryTask 'WinRTCSBootstrapResume'
if ((-not $resume.Absent) -and -not $Continue) {
    Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Emit 'STATE=FAILED'
    Emit 'FAILURE_CODE=INSTALL_STORM'
    exit 4
}

function Write-LocalDeviceKey {
    $keyPath = Join-Path $script:CanaryRoot 'key.json'
    if (Test-Path -LiteralPath $keyPath) { return }
    $rsa = [Security.Cryptography.RSA]::Create(2048)
    try {
        $parameters = $rsa.ExportParameters($true)
        $material = [ordered]@{
            modulus = [Convert]::ToBase64String($parameters.Modulus)
            exponent = [Convert]::ToBase64String($parameters.Exponent)
            d = [Convert]::ToBase64String($parameters.D)
            p = [Convert]::ToBase64String($parameters.P)
            q = [Convert]::ToBase64String($parameters.Q)
            dp = [Convert]::ToBase64String($parameters.DP)
            dq = [Convert]::ToBase64String($parameters.DQ)
            inverseq = [Convert]::ToBase64String($parameters.InverseQ)
        }
        $utf8 = New-Object Text.UTF8Encoding $false
        [IO.File]::WriteAllText($keyPath, ($material | ConvertTo-Json -Compress), $utf8)
    } finally { $rsa.Dispose() }
    & icacls.exe $keyPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
}
function Publish-ScreenConnectPolicy {
    Emit 'SCREENCONNECT_POLICY=NOT_ENFORCED'
    Emit 'SCREENCONNECT_PROHIBITED_LIST=EMPTY'
    Emit 'SCREENCONNECT_ACTION=NONE'
    Emit 'SCREENCONNECT_ACTION_REASON=explicit_prohibited_ids_not_configured'
    Emit 'SCREENCONNECT_SHARED_PRODUCTCODE_UNINSTALL=REFUSED'
    Emit 'SCREENCONNECT_COMPLIANCE=NOT_CLAIMED'
    $approved = @{
        '41b1cb0dd5f78b27' = 'APPROVED_PRIMARY'
        '1432e226cdbd6e78' = 'APPROVED_BACKUP'
    }
    $found = 0
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $services = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'ScreenConnect*' })
    $ErrorActionPreference = $preference
    foreach ($svc in $services) {
        $found += 1
        $name = [string]$svc.Name
        $id = 'UNPARSED'
        $class = 'UNKNOWN_NO_ACTION'
        if ($name -match '^ScreenConnect Client \(([0-9a-fA-F]{16})\)$') {
            $id = $Matches[1].ToLowerInvariant()
            if ($approved.ContainsKey($id)) { $class = [string]$approved[$id] }
            elseif ($id -eq '36e506ff016b2151') { $class = 'UNTRUSTED_AUTO_REMOVAL_DISABLED' }
        }
        Emit ('SCREENCONNECT_INSTANCE=' + $name + ' ID=' + $id + ' CLASS=' + $class + ' SERVICE_STATE=' + [string]$svc.Status)
    }
    if ($found -eq 0) { Emit 'SCREENCONNECT_DETECTED=NONE' }
}
function Publish-InstallSplit([string]$LocalState, [hashtable]$Keeper, [int]$WatchExit) {
    Publish-ScreenConnectPolicy
    if ($LocalState -eq 'SUCCEEDED') { Write-LocalDeviceKey }
    $continuityStatus = Join-Path $script:CanaryRoot 'continuity-status.txt'
    $watchdog = 'ABSENT'
    if (Test-Path -LiteralPath $continuityStatus) {
        foreach ($line in [IO.File]::ReadAllLines($continuityStatus)) {
            if ($line.StartsWith('watchdog=')) { $watchdog = $line.Substring(9).Trim() }
        }
    }
    Emit ('LOCAL_INSTALL_STATE=' + $LocalState)
    Emit 'CORE_FILES=PRESENT'
    Emit 'CORE_STATE=INSTALLED'
    Emit 'CORE_OPERATION=NOT_PROVEN'
    Emit ('CONTINUITY_WATCH_EXIT=' + $WatchExit)
    Emit ('CONTINUITY_WATCHDOG=' + $watchdog)
    $primary = [string]$Keeper['primary_local_health']
    $backup = [string]$Keeper['backup_local_health']
    Emit ('PULSV_SERVICE=' + $(if ($primary -eq 'HEALTHY') { 'RUNNING' } else { 'UNVERIFIED' }))
    Emit 'PULSV_FUNCTIONAL=UNVERIFIED'
    Emit 'PULSV_REASON=primary_relay_reachability=not_checked'
    Emit ('BACKUP_SERVICE=' + $(if ($backup -eq 'HEALTHY') { 'RUNNING' } else { 'UNVERIFIED' }))
    Emit 'BACKUP_FUNCTIONAL=UNVERIFIED'
    Emit 'BACKUP_REASON=relay_not_checked'
    Emit 'TACTICAL_STATE=NOT_INTEGRATED'
    Emit 'TACTICAL_REASON=server_queue_token_required'
    Emit 'BACKEND_STATE=NOT_ENROLLED'
    Emit ('PULSV_STATE=' + $(if ($primary -eq 'HEALTHY') { 'RUNNING_RELAY_UNCHECKED' } else { 'UNVERIFIED' }))
    Emit ('BACKUP_STATE=' + $(if ($backup -eq 'HEALTHY') { 'RUNNING_RELAY_UNCHECKED' } else { 'UNVERIFIED' }))
    Emit 'POLICY_STATE=NOT_ENFORCED'
    Emit 'UPDATE_STATE=UNVERIFIED'
    Emit 'BACKEND_REASON=no_telemetry_registration_on_production'
    if ($LocalState -eq 'SUCCEEDED') {
        Emit 'OVERALL_STATE=PARTIAL'
        Emit 'PULSV=RUNNING'
        Emit 'SECZIO=RUNNING'
    } else {
        Emit 'OVERALL_STATE=FAILED'
        Emit 'STATE=FAILED'
    }
}
function Invoke-LocalInstall([string]$Stage) {
    $runFile = Join-Path $script:CanaryRoot 'canary-run.id'
    $handoffRun = ''
    if (Test-Path -LiteralPath $runFile) { $handoffRun = ([IO.File]::ReadAllText($runFile)).Trim() }
    Write-Handoff ('INSTALL_STARTED=true RUN_ID=' + $handoffRun)
    Emit 'STATE=IN_PROGRESS'
    Emit 'INSTALL_MODE=local'
    $cache = 'C:\ProgramData\Microsoft\WinRTCS\cache'
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    New-Item -ItemType Directory -Force -Path $script:CanaryRoot | Out-Null
    $names = @(
        'winrtcs.version','winrtcs.version.sig',
        'winrtcs_agent.cmd','winrtcs_guard.cmd','winrtcs_sentinel.cmd','winrtcs_run.cmd',
        'winrtcs_gen_commit.ps1','winrtcs_device_client.ps1','winrtcs_device.cfg',
        'winrtcs_continuity.ps1','winrtcs_watchdog.cmd','winrtcs_wdgate.cmd','winrtcs_keeper.ps1'
    )
    foreach ($name in $names) {
        $source = Join-Path $Stage $name
        if (-not (Test-Path -LiteralPath $source)) {
            Write-Handoff ('INSTALL_FAILED=true RUN_ID=' + $handoffRun + ' FAILURE_CODE=COMPONENT_MISSING')
            Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
            Emit 'STATE=FAILED'
            Emit 'LOCAL_INSTALL_STATE=FAILED'
            Emit 'BACKEND_STATE=NOT_ENROLLED'
            Emit 'FAILURE_CODE=COMPONENT_MISSING'
            exit 3
        }
        Copy-Item -LiteralPath $source -Destination (Join-Path $cache $name) -Force
    }
    $commit = Join-Path $cache 'winrtcs_gen_commit.ps1'
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $commit -Repair
    $commitCode = $LASTEXITCODE
    $ErrorActionPreference = $preference
    $commitResult = ''
    $resultPath = Join-Path $script:CanaryRoot 'gen-commit-result.txt'
    if (Test-Path -LiteralPath $resultPath) { $commitResult = ([IO.File]::ReadAllText($resultPath)).Trim() }
    if ($commitCode -ne 0 -or ($commitResult -ne 'NEW_COMPLETE' -and $commitResult -ne 'IDEMPOTENT')) {
        Write-Handoff ('INSTALL_FAILED=true RUN_ID=' + $handoffRun + ' FAILURE_CODE=GENERATION_COMMIT')
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'LOCAL_INSTALL_STATE=FAILED'
        Emit 'BACKEND_STATE=NOT_ENROLLED'
        Emit 'FAILURE_CODE=GENERATION_COMMIT'
        Emit ('INSTALL_EXIT=' + $commitCode)
        exit 4
    }
    $keeper = Join-Path $script:CanaryRoot 'winrtcs_keeper.ps1'
    $env:WINRTCS_REBOOT_POLICY = $script:RebootPolicy
    Emit ('KEEPER_REBOOT_POLICY=' + $script:RebootPolicy)
    $ErrorActionPreference = 'Continue'
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $keeper -Action Ensure
    $keeperCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    $keeperMap = @{}
    $keeperStatus = Join-Path $script:CanaryRoot 'keeper-status.txt'
    if (Test-Path -LiteralPath $keeperStatus) {
        foreach ($line in [IO.File]::ReadAllLines($keeperStatus)) {
            $pair = $line.Split('=', 2)
            if ($pair.Length -eq 2) { $keeperMap[$pair[0].Trim()] = $pair[1].Trim() }
        }
    }
    if ([string]$keeperMap['KEEPER_INSTALL_REBOOT_REQUIRED'] -eq 'true') {
        Write-Handoff ('INSTALL_REBOOT_REQUIRED=true RUN_ID=' + $handoffRun)
        Emit 'LOCAL_INSTALL_STATE=IN_PROGRESS'
        Emit 'BACKEND_STATE=NOT_ENROLLED'
        Register-CanaryReboot ''
    }
    if ($keeperCode -ne 0 -or [string]$keeperMap['KEEPER_HEALTH'] -ne 'HEALTHY') {
        Write-Handoff ('INSTALL_FAILED=true RUN_ID=' + $handoffRun + ' FAILURE_CODE=KEEPER_ENSURE')
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'LOCAL_INSTALL_STATE=FAILED'
        Emit 'BACKEND_STATE=NOT_ENROLLED'
        Emit 'FAILURE_CODE=KEEPER_ENSURE'
        Emit ('INSTALL_EXIT=' + $keeperCode)
        exit 4
    }
    $pulsv = Test-ServiceRunning 'ScreenConnect Client (41b1cb0dd5f78b27)'
    $seczio = Test-ServiceRunning 'ScreenConnect Client (1432e226cdbd6e78)'
    if (-not $pulsv -or -not $seczio) {
        Write-Handoff ('INSTALL_FAILED=true RUN_ID=' + $handoffRun + ' FAILURE_CODE=GUEST_SERVICE_NOT_RUNNING')
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'LOCAL_INSTALL_STATE=FAILED'
        Emit 'BACKEND_STATE=NOT_ENROLLED'
        Emit 'FAILURE_CODE=GUEST_SERVICE_NOT_RUNNING'
        exit 4
    }
    $continuity = Join-Path $script:CanaryRoot 'winrtcs_continuity.ps1'
    $ErrorActionPreference = 'Continue'
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $continuity -Action Prepare
    $prepare = $LASTEXITCODE
    $watchExit = -1
    if ($prepare -eq 0) {
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $continuity -Action Watch | Out-Null
        $watchExit = $LASTEXITCODE
    }
    $ErrorActionPreference = 'Stop'
    if ($prepare -ne 0) {
        Write-Handoff ('INSTALL_FAILED=true RUN_ID=' + $handoffRun + ' FAILURE_CODE=TASK_CREATE')
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'LOCAL_INSTALL_STATE=FAILED'
        Emit 'BACKEND_STATE=NOT_ENROLLED'
        Emit 'FAILURE_CODE=TASK_CREATE'
        exit 4
    }
    $generation = Get-Sha256File (Join-Path $cache 'winrtcs.version')
    Emit ('GENERATION=' + $generation)
    if ($handoffRun -match '^[0-9a-f]{32}$') {
        Write-RunProvenance $handoffRun @{ run_id = $handoffRun; stage = 'COMMITTED_GENERATION'; generation_sha256 = $generation; reboot_policy = $script:RebootPolicy }
        Emit 'PROVENANCE_STAGE=COMMITTED_GENERATION'
        Emit 'GENERATION_COMMITTED=true'
    }
    Emit 'INSTALL_COMPLETED=true'
    Write-Handoff ('INSTALL_COMPLETED=true RUN_ID=' + $handoffRun)
    Publish-InstallSplit 'SUCCEEDED' $keeperMap $watchExit
    exit 0
}

if ($Continue) {
    if ($StagePath -notmatch '\\winrtcs-canary-[0-9a-f]{32}\z') {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'FAILURE_CODE=STAGE_PATH'
        exit 4
    }
    Invoke-LocalInstall $StagePath
}

$stage = Join-Path $script:CanaryRoot ('winrtcs-canary-' + [guid]::NewGuid().ToString('n'))
$cleanup = $true
try {
    New-Item -ItemType Directory -Path $stage | Out-Null
    $acl = Get-Acl -LiteralPath $stage
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl -LiteralPath $stage -AclObject $acl
    Emit 'STATE=VERIFYING'
    $bootstrap = Join-Path $stage 'winrtcs_zero_state_bootstrap.ps1'
    $version = Join-Path $stage 'winrtcs.version'
    $signature = Join-Path $stage 'winrtcs.version.sig'
    Receive-File 'winrtcs_zero_state_bootstrap.ps1' $bootstrap
    if ((Get-Sha256File $bootstrap) -ne $ExpectedBootstrap) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'FAILURE_CODE=BOOTSTRAP_HASH'
        exit 3
    }
    Receive-File 'winrtcs.version' $version
    Receive-File 'winrtcs.version.sig' $signature
    $bootText = [IO.File]::ReadAllText($bootstrap)
    $mod = [regex]::Match($bootText, "GenerationModulus = '([^']+)'").Groups[1].Value
    $sigText = [IO.File]::ReadAllText($signature)
    $sigB64 = [regex]::Match($sigText, '(?m)^sig=([A-Za-z0-9+/=]+)\s*$').Groups[1].Value
    $publisher = New-Object Security.Cryptography.RSACryptoServiceProvider
    $params = New-Object Security.Cryptography.RSAParameters
    $params.Modulus = [Convert]::FromBase64String($mod)
    $params.Exponent = [Convert]::FromBase64String('AQAB')
    $publisher.ImportParameters($params)
    $versionBytes = [IO.File]::ReadAllBytes($version)
    if (-not $sigB64 -or -not $publisher.VerifyData($versionBytes, 'SHA256', [Convert]::FromBase64String($sigB64))) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'FAILURE_CODE=BAD_SIGNATURE'
        exit 3
    }
    $pins = @{}
    foreach ($line in [IO.File]::ReadAllLines($version)) {
        $pair = $line.Split('=', 2)
        if ($pair.Length -eq 2) { $pins[$pair[0].Trim()] = $pair[1].Trim() }
    }
    $map = @{
        'winrtcs_agent.cmd' = 'AGENT_SHA256'
        'winrtcs_guard.cmd' = 'GUARD_SHA256'
        'winrtcs_sentinel.cmd' = 'SENTINEL_SHA256'
        'winrtcs_run.cmd' = 'RUN_SHA256'
        'winrtcs_gen_commit.ps1' = 'COMMIT_SHA256'
        'winrtcs_device_client.ps1' = 'CLIENT_SHA256'
        'winrtcs_device.cfg' = 'CONFIG_SHA256'
        'winrtcs_continuity.ps1' = 'CONTINUITY_SHA256'
        'winrtcs_watchdog.cmd' = 'WATCHDOG_SHA256'
        'winrtcs_wdgate.cmd' = 'LAUNCHER_SHA256'
        'winrtcs_keeper.ps1' = 'KEEPER_SHA256'
    }
    foreach ($name in $map.Keys) {
        $dest = Join-Path $stage $name
        Receive-File $name $dest
        if ((Get-Sha256File $dest) -ne ([string]$pins[$map[$name]]).ToLowerInvariant()) {
            Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
            Emit 'FAILURE_CODE=COMPONENT_HASH'
            exit 3
        }
    }
    Emit 'INSTALL_MODE=local'
    $runId = [guid]::NewGuid().ToString('n')
    $existingTask = Get-CanaryTask 'WinRTCSCanaryInstall'
    if (-not $existingTask.Absent -and $existingTask.State -eq 'Running') {
        Emit ('RUN_ID=' + $runId)
        Emit 'TASK_STATE=RUNNING'
        Emit 'TASK_NAME=WinRTCSCanaryInstall'
        Emit 'HANDOFF=PENDING'
        Emit 'FOREGROUND_RESULT=SCHEDULED_ONLY'
        Emit 'STATE=IN_PROGRESS'
        exit 0
    }
    $wrapperPath = Join-Path $script:CanaryRoot 'winrtcs_canary_unattended.ps1'
    if (-not $existingTask.Absent -and $existingTask.Action -notlike ('*' + $wrapperPath + '*')) {
        Emit 'TASK_DEFINITION=STALE'
        $previousFile = ''
        $fileMatch = [regex]::Match([string]$existingTask.Action, '(?i)-File\s+"?([^"\s]+)')
        if ($fileMatch.Success) { $previousFile = $fileMatch.Groups[1].Value }
        if ($previousFile) { Emit ('TASK_PREVIOUS_FILE=' + $previousFile) }
        Emit ('TASK_PREVIOUS_RESULT=' + (Format-TaskResult $existingTask.LastResult))
    }
    $wrapper = @'
$prov = 'C:\ProgramData\WinRTCS\runs\__RUN__\provenance.txt'
$expectedWorker = ''
$expectedPath = ''
if (Test-Path -LiteralPath $prov) {
    foreach ($line in [IO.File]::ReadAllLines($prov)) {
        if ($line.StartsWith('worker_sha256=')) { $expectedWorker = $line.Substring(15).Trim().ToLowerInvariant() }
        if ($line.StartsWith('worker_path=')) { $expectedPath = $line.Substring(12).Trim() }
    }
}
$actualWorker = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not $expectedWorker -or $actualWorker -ne $expectedWorker -or $PSCommandPath.Trim().ToLowerInvariant() -ne $expectedPath.Trim().ToLowerInvariant()) {
    [IO.File]::AppendAllText('__HANDOFF__', (([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) + ' FAILURE_CODE=WORKER_IDENTITY RUN_ID=__RUN__' + "`r`n"))
    exit 3
}
[IO.File]::AppendAllText('__HANDOFF__', (([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) + ' WORKER_ENTERED=true RUN_ID=__RUN__' + "`r`n"))
& powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '__LAUNCHER__' -Continue -StagePath '__STAGE__' -RunId '__RUN__' -RebootPolicy '__POLICY__'
$code = $LASTEXITCODE
[IO.File]::AppendAllText('__HANDOFF__', (([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) + ' WORKER_EXIT=' + $code + ' RUN_ID=__RUN__' + "`r`n"))
[IO.File]::AppendAllText('C:\ProgramData\WinRTCS\canary-install.log', (([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) + ' WRAPPER_EXIT=' + $code + "`r`n"))
exit $code
'@
    $launcherCopy = Join-Path $script:CanaryRoot 'winrtcs_canary_launcher.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $launcherCopy -Force
    & icacls.exe $launcherCopy /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    $handoffPath = Join-Path $script:CanaryRoot 'canary-handoff.txt'
    $quotedLauncher = $launcherCopy.Replace("'", "''")
    $quotedStage = $stage.Replace("'", "''")
    $wrapperText = $wrapper.Replace('__LAUNCHER__', $quotedLauncher).Replace('__STAGE__', $quotedStage).Replace('__HANDOFF__', $handoffPath.Replace("'", "''")).Replace('__RUN__', $runId).Replace('__POLICY__', $script:RebootPolicy)
    [IO.File]::WriteAllText($wrapperPath, $wrapperText)
    & icacls.exe $wrapperPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    $workerHash = Get-Sha256File $wrapperPath
    $foregroundHash = Get-Sha256File $launcherCopy
    Write-RunProvenance $runId @{
        run_id = $runId
        stage = 'EXECUTED_FOREGROUND'
        source_url = [string]$SourceUrl
        expected_sha256 = ([string]$ExpectedSha256).Trim().ToLowerInvariant()
        foreground_path = $launcherCopy
        foreground_sha256 = $foregroundHash
        worker_path = $wrapperPath
        worker_sha256 = $workerHash
        reboot_policy = $script:RebootPolicy
    }
    Emit 'PROVENANCE_STAGE=EXECUTED_FOREGROUND'
    Emit 'FOREGROUND_VERIFIED=true'
    Emit ('WORKER_SHA256=' + $workerHash)
    $runFile = Join-Path $script:CanaryRoot 'canary-run.id'
    [IO.File]::WriteAllText($runFile, $runId)
    & icacls.exe $runFile /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    $taskArgs = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $wrapperPath + '"'
    $xmlArgs = $taskArgs.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    $xmlPath = Join-Path $script:CanaryRoot 'canary-task.xml'
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT4H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>$xmlArgs</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    $utf16 = New-Object System.Text.UnicodeEncoding $false, $true
    [IO.File]::WriteAllText($xmlPath, $xml, $utf16)
    Write-Handoff ('TASK_REQUESTED=true RUN_ID=' + $runId)
    Emit 'HANDOFF=TASK_REQUESTED'
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $createText = @(& schtasks.exe /Create /TN 'WinRTCSCanaryInstall' /XML $xmlPath /F 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $createCode = $LASTEXITCODE
    $runCode = 1
    if ($createCode -eq 0) {
        & schtasks.exe /Run /TN 'WinRTCSCanaryInstall' 2>&1 | Out-Null
        $runCode = $LASTEXITCODE
    }
    $ErrorActionPreference = $preference
    Remove-Item -LiteralPath $xmlPath -Force -ErrorAction SilentlyContinue
    if ($createCode -ne 0 -or $runCode -ne 0) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'FAILURE_CODE=SCHEDULER_START_FAILED'
        if ($createText) { Write-CanaryLog 'SCHEDULER_CREATE_FAILED' }
        exit 4
    }
    $cleanup = $false
    Emit ('RUN_ID=' + $runId)
    Emit 'WINRTCS_CANARY_STARTED=true'
    Emit 'TASK_NAME=WinRTCSCanaryInstall'
    Emit ('TASK_WRAPPER=' + $wrapperPath)
    Emit ('STAGE_PATH=' + $stage)
    Emit 'TASK_IDENTITY=S-1-5-18'
    Write-RunProvenance $runId @{ run_id = $runId; stage = 'REGISTERED_WORKER'; reboot_policy = $script:RebootPolicy }
    Emit 'PROVENANCE_STAGE=REGISTERED_WORKER'
    Emit 'WORKER_ARMED=true'
    Emit 'SCHTASKS_RUN=0'
    Emit 'FOREGROUND_RESULT=SCHEDULED_ONLY'
    $entered = $false
    for ($wait = 0; $wait -lt 12; $wait++) {
        if (Test-WorkerEntered $runId) { $entered = $true; break }
        Start-Sleep -Seconds 1
    }
    $afterTask = Get-CanaryTask 'WinRTCSCanaryInstall'
    Emit 'LOG=C:\ProgramData\WinRTCS\canary-install.log'
    if ($entered) {
        Write-RunProvenance $runId @{ run_id = $runId; stage = 'RUNNING_WORKER'; reboot_policy = $script:RebootPolicy }
        Emit 'PROVENANCE_STAGE=RUNNING_WORKER'
        Emit 'WORKER_ENTERED=true'
        Emit 'HANDOFF=WORKER_ENTERED'
        Emit 'FOREGROUND_RESULT=WORKER_ENTERED'
        Emit 'STATE=IN_PROGRESS'
        exit 0
    }
    if ($afterTask.State -eq 'Running' -or $afterTask.State -eq 'Queued') {
        Emit 'HANDOFF=PENDING'
        Emit ('TASK_SCHEDULER_STATE=' + $afterTask.State)
        Emit 'STATE=IN_PROGRESS'
        exit 0
    }
    Emit 'HANDOFF=WORKER_NOT_ENTERED'
    Emit ('TASK_LAST_RESULT=' + $afterTask.LastResult)
    Emit ('TASK_EXIT_CODE=' + $afterTask.LastResult)
    if ([string]$afterTask.LastResult -eq '-1073741502') {
        Emit ('TASK_NTSTATUS=' + (Format-TaskResult $afterTask.LastResult))
        Emit 'FAILURE_CODE=TASK_STARTUP'
        Emit 'FAULTING_MODULE=UNKNOWN'
        Emit 'STATE=FAILED'
        exit 4
    }
    Emit ('TASK_SCHEDULER_STATE=' + $afterTask.State)
    Emit 'FAILURE_CODE=WORKER_NOT_ENTERED'
    Emit 'STATE=IN_PROGRESS'
    exit 0
} catch {
    $detail = Get-CanaryErrorText $_
    Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Emit 'FAILURE_CODE=STAGE'
    Emit 'STAGE_OPERATION=foreground'
    Emit ('STAGE_ERROR=' + $detail.Chain)
    if ($detail.Status) { Emit ('STAGE_STATUS=' + $detail.Status) }
    if ($detail.Message) { Emit ('STAGE_DETAIL=' + $detail.Message) }
    exit 3
} finally {
    if ($cleanup -and (Test-Path -LiteralPath $stage)) {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}
