# WinRTCS physical canary. Signature and component hashes are checked before enrollment.
# UPDATE_V2_INCLUDED=false
# CANARY_UNATTENDED=1
param(
    [switch]$Continue,
    [switch]$PostReboot,
    [string]$StagePath = ''
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::CheckCertificateRevocationList = $true
if ($null -ne [Net.ServicePointManager]::ServerCertificateValidationCallback) {
    Write-Output 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Write-Output 'STATE=FAILED'
    Write-Output 'FAILURE_CODE=TLS_CALLBACK'
    exit 2
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Write-Output 'STATE=FAILED'
    Write-Output 'FAILURE_CODE=ADMINISTRATOR_REQUIRED'
    exit 1
}
$SoftwareBase = 'https://raw.githubusercontent.com/Byteverait/winrtcs-physical-canary-delivery/main'
$DeviceBase = 'https://device.seczio.com'
$ExpectedBootstrap = '0a62d34817f218df4cdf17f48b6d56ac767131843614842360551c7ab58880b7'
$script:CanaryLog = 'C:\ProgramData\WinRTCS\canary-install.log'
$script:CanaryRoot = 'C:\ProgramData\WinRTCS'

function Write-CanaryLog([string]$Line) {
    if ($Line -match '(?i)token=|sig=|BEGIN ') { return }
    $stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    [IO.File]::AppendAllText($script:CanaryLog, ($stamp + ' ' + $Line + "`r`n"))
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
    $createdRoot = -not (Test-Path -LiteralPath $script:CanaryRoot)
    if ($createdRoot) {
        New-Item -ItemType Directory -Path $script:CanaryRoot | Out-Null
        & icacls.exe $script:CanaryRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
    }
    if (-not (Test-Path -LiteralPath $script:CanaryLog)) {
        [IO.File]::WriteAllText($script:CanaryLog, '')
    }
    & icacls.exe $script:CanaryLog /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
}
function Get-CanaryTask([string]$Name) {
    $found = [pscustomobject]@{ Absent = $true; State = '' }
    try {
        $task = Get-ScheduledTask -TaskName $Name -ErrorAction Stop
        $found.Absent = $false
        $found.State = [string]$task.State
    } catch {
        $id = [string]$_.FullyQualifiedErrorId
        $msg = [string]$_.Exception.Message
        $absent = $id.StartsWith('CmdletizationQuery_NotFound') -or $msg.Contains('No MSFT_ScheduledTask objects found')
        if (-not $absent) { throw }
    }
    return $found
}
function Get-Sha256File([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Receive-File([string]$Name, [string]$Dest) {
    for ($try = 1; $try -le 3; $try++) {
        try {
            Invoke-WebRequest -Uri ($SoftwareBase + '/' + $Name) -OutFile $Dest -UseBasicParsing
            return
        } catch {
            if ($try -lt 3) { Start-Sleep -Seconds (2 * $try) }
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
    Emit 'REBOOT_REQUIRED=true'
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
    if ($prepare -eq 0) {
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $continuity -Action Watch | Out-Null
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
    $client = Join-Path $script:CanaryRoot 'winrtcs_device_client.ps1'
    $ErrorActionPreference = 'Continue'
    $tick = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $client -Action Tick -WorkDir $script:CanaryRoot 2>&1 | Out-String
    $ErrorActionPreference = 'Stop'
    if ($tick -notmatch 'DEVICE_TICK=active') {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=HEARTBEAT_OR_POLL'
        exit 4
    }
    $generation = Get-Sha256File $version
    $status = ''
    if (Test-Path 'C:\Windows\Temp\winrtcs-bootstrap-status.txt') {
        $status = [IO.File]::ReadAllText('C:\Windows\Temp\winrtcs-bootstrap-status.txt')
    }
    if ($status -notmatch [regex]::Escape('GENERATION=' + $generation)) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=GENERATION_MISMATCH'
        exit 4
    }
    $resumeFile = Join-Path $script:CanaryRoot 'bootstrap-resume.txt'
    if (Test-Path -LiteralPath $resumeFile) { Remove-Item -LiteralPath $resumeFile -Force }
    Emit 'WINRTCS_PHYSICAL_CANARY=PASS'
    Emit 'STATE=SUCCEEDED'
    Emit ('GENERATION=' + $generation)
    Emit 'DEVICE_STATE=DEVICE_ACTIVE'
    Emit 'PULSV=RUNNING'
    Emit 'SECZIO=RUNNING'
    Emit 'HEARTBEAT=PASS'
    Emit 'POLL=PASS'
    exit 0
}

Initialize-CanaryLog
if ($PostReboot) {
    Invoke-PostReboot
}
$installed = (Test-ServiceRunning 'ScreenConnect Client (41b1cb0dd5f78b27)') -and (Test-ServiceRunning 'ScreenConnect Client (1432e226cdbd6e78)') -and (Test-Path -LiteralPath 'C:\ProgramData\WinRTCS\winrtcs_device_client.ps1')
if ($installed -and -not $Continue) {
    Emit 'WINRTCS_PHYSICAL_CANARY=ALREADY_INSTALLED'
    Emit 'STATE=SUCCEEDED'
    Emit 'PULSV=RUNNING'
    Emit 'SECZIO=RUNNING'
    exit 0
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

function Invoke-CanaryTail([string]$Stage, [string]$Enroll) {
    Emit 'STATE=IN_PROGRESS'
    $bootstrap = Join-Path $Stage 'winrtcs_zero_state_bootstrap.ps1'
    $version = Join-Path $Stage 'winrtcs.version'
    Remove-Item Env:WINRTCS_LAB_REBOOT_ALLOWED -ErrorAction SilentlyContinue
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $bootstrap -DeviceBase $DeviceBase -EnrollmentFile $Enroll -SoftwareBase $SoftwareBase
    $code = $LASTEXITCODE
    $ErrorActionPreference = $preference
    $status = ''
    if (Test-Path 'C:\Windows\Temp\winrtcs-bootstrap-status.txt') {
        $status = [IO.File]::ReadAllText('C:\Windows\Temp\winrtcs-bootstrap-status.txt')
    }
    if ($code -eq 4 -and $status -match 'REBOOT_RESUME=armed' -and $status -notmatch 'INSTALL_BLOCKED=reboot-loop') {
        Register-CanaryReboot $Enroll
    }
    if ($code -ne 0) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=INSTALL_FAILED'
        Emit ('INSTALL_EXIT=' + $code)
        exit $code
    }
    $pulsv = Test-ServiceRunning 'ScreenConnect Client (41b1cb0dd5f78b27)'
    $seczio = Test-ServiceRunning 'ScreenConnect Client (1432e226cdbd6e78)'
    if (-not $pulsv -or -not $seczio) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'FAILURE_CODE=GUEST_SERVICE_NOT_RUNNING'
        exit 4
    }
    $client = 'C:\ProgramData\WinRTCS\winrtcs_device_client.ps1'
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $tick = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $client -Action Tick -WorkDir 'C:\ProgramData\WinRTCS' 2>&1 | Out-String
    $ErrorActionPreference = $preference
    if ($tick -notmatch 'DEVICE_TICK=active') {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'FAILURE_CODE=HEARTBEAT_OR_POLL'
        exit 4
    }
    $generation = Get-Sha256File $version
    $status = ''
    if (Test-Path 'C:\Windows\Temp\winrtcs-bootstrap-status.txt') {
        $status = [IO.File]::ReadAllText('C:\Windows\Temp\winrtcs-bootstrap-status.txt')
    }
    if ($status -notmatch [regex]::Escape('GENERATION=' + $generation)) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'FAILURE_CODE=GENERATION_MISMATCH'
        exit 4
    }
    $pins = @{}
    foreach ($line in [IO.File]::ReadAllLines($version)) {
        $pair = $line.Split('=', 2)
        if ($pair.Length -eq 2) { $pins[$pair[0].Trim()] = $pair[1].Trim() }
    }
    Emit 'WINRTCS_PHYSICAL_CANARY=PASS'
    Emit ('VERSION=' + [string]$pins['WINRTCS_VER'])
    Emit ('GENERATION=' + $generation)
    Emit 'DEVICE_STATE=DEVICE_ACTIVE'
    Emit 'PULSV=RUNNING'
    Emit 'SECZIO=RUNNING'
    Emit 'HEARTBEAT=PASS'
    Emit 'POLL=PASS'
    Emit 'UPDATE_V2=DEFERRED_CANARY_SCOPE'
    exit 0
}

if ($Continue) {
    if ($StagePath -notmatch '\\winrtcs-canary-[0-9a-f]{32}\z') {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'FAILURE_CODE=STAGE_PATH'
        exit 4
    }
    $enroll = Join-Path $StagePath 'enroll.txt'
    if (-not (Test-Path -LiteralPath $enroll)) {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'FAILURE_CODE=ENROLLMENT_FILE_MISSING'
        exit 3
    }
    Invoke-CanaryTail $StagePath $enroll
}

$stage = Join-Path $env:TEMP ('winrtcs-canary-' + [guid]::NewGuid().ToString('n'))
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
    Emit 'STATE=CLAIMING'
    $token = $null
    $claimFailure = 'CLAIM_UNREACHABLE'
    for ($try = 1; $try -le 3 -and [string]::IsNullOrWhiteSpace($token); $try++) {
        $request = [Net.HttpWebRequest]::Create([Uri]($DeviceBase + '/device/control/bootstrap/claim'))
        $request.Method = 'POST'
        $request.Timeout = 20000
        $request.AllowAutoRedirect = $false
        $request.ContentType = 'application/json'
        $bodyBytes = [Text.Encoding]::ASCII.GetBytes('{}')
        $request.ContentLength = $bodyBytes.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($bodyBytes, 0, $bodyBytes.Length) } finally { $stream.Close() }
        try {
            $response = $request.GetResponse()
            try {
                $reader = New-Object IO.StreamReader($response.GetResponseStream())
                try { $payload = $reader.ReadToEnd() } finally { $reader.Close() }
            } finally { $response.Close() }
            $parsed = $payload | ConvertFrom-Json
            $token = [string]$parsed.token
            $payload = $null
            $parsed = $null
        } catch [Net.WebException] {
            $statusCode = 0
            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
            if ($statusCode -eq 403) { $claimFailure = 'CLAIM_DENIED'; break }
            if ($try -lt 3) { Start-Sleep -Seconds (2 * $try) }
        }
    }
    if ([string]::IsNullOrWhiteSpace($token) -and $claimFailure -eq 'CLAIM_UNREACHABLE') {
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'STATE=FAILED'
        Emit 'FAILURE_CODE=CLAIM_UNREACHABLE'
        exit 3
    }
    if ([string]::IsNullOrWhiteSpace($token)) {
        $token = $null
        Emit 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Emit 'FAILURE_CODE=CLAIM_DENIED'
        exit 3
    }
    $enroll = Join-Path $stage 'enroll.txt'
    $utf8 = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllText($enroll, $token.Trim(), $utf8)
    $token = $null
    $runId = [guid]::NewGuid().ToString('n')
    $wrapper = @'
& powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '__LAUNCHER__' -Continue -StagePath '__STAGE__'
$code = $LASTEXITCODE
[IO.File]::AppendAllText('C:\ProgramData\WinRTCS\canary-install.log', (([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) + ' WRAPPER_EXIT=' + $code + "`r`n"))
exit $code
'@
    $quotedLauncher = $PSCommandPath.Replace("'", "''")
    $quotedStage = $stage.Replace("'", "''")
    $wrapperPath = Join-Path $env:TEMP 'winrtcs_canary_unattended.ps1'
    [IO.File]::WriteAllText($wrapperPath, $wrapper.Replace('__LAUNCHER__', $quotedLauncher).Replace('__STAGE__', $quotedStage))
    $taskArgs = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $wrapperPath + '"'
    $xmlArgs = $taskArgs.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    $xmlPath = Join-Path $env:TEMP 'winrtcs-canary-unattended.xml'
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
    Emit 'LOG=C:\ProgramData\WinRTCS\canary-install.log'
    Emit 'STATE=STARTED'
    exit 0
} finally {
    if ($cleanup -and (Test-Path -LiteralPath $stage)) {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}
