# WinRTCS physical canary. Signature and component hashes are checked before the token prompt.
# UPDATE_V2_INCLUDED=false
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::CheckCertificateRevocationList = $true
if ($null -ne [Net.ServicePointManager]::ServerCertificateValidationCallback) {
    Write-Output 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Write-Output 'FAILURE_CODE=TLS_CALLBACK'
    exit 2
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Write-Output 'FAILURE_CODE=ADMINISTRATOR_REQUIRED'
    exit 1
}
$prior = $null
try {
    $prior = Get-ScheduledTask -TaskName 'WinRTCSBootstrapResume' -ErrorAction Stop
} catch {
    $id = [string]$_.FullyQualifiedErrorId
    $msg = [string]$_.Exception.Message
    $absent = $id.StartsWith('CmdletizationQuery_NotFound') -or $msg.Contains('No MSFT_ScheduledTask objects found')
    if (-not $absent) {
        Write-Output 'WINRTCS_PHYSICAL_CANARY=FAIL'
        Write-Output 'FAILURE_CODE=SCHEDULER_QUERY_FAILED'
        exit 4
    }
}
if ($null -ne $prior) {
    Write-Output 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Write-Output 'FAILURE_CODE=INSTALL_STORM'
    exit 4
}
$SoftwareBase = 'https://raw.githubusercontent.com/Byteverait/winrtcs-physical-canary-delivery/main'
$DeviceBase = 'https://device.seczio.com'
$ExpectedBootstrap = '0a62d34817f218df4cdf17f48b6d56ac767131843614842360551c7ab58880b7'
$stage = Join-Path $env:TEMP ('winrtcs-canary-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $stage | Out-Null
$acl = Get-Acl -LiteralPath $stage
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -LiteralPath $stage -AclObject $acl
function Get-Sha256File([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Receive-File([string]$Name, [string]$Dest) {
    Invoke-WebRequest -Uri ($SoftwareBase + '/' + $Name) -OutFile $Dest -UseBasicParsing
}
function Fail([string]$Code) {
    Write-Output 'WINRTCS_PHYSICAL_CANARY=FAIL'
    Write-Output ('FAILURE_CODE=' + $Code)
}
$bootstrap = Join-Path $stage 'winrtcs_zero_state_bootstrap.ps1'
$version = Join-Path $stage 'winrtcs.version'
$signature = Join-Path $stage 'winrtcs.version.sig'
try {
    Receive-File 'winrtcs_zero_state_bootstrap.ps1' $bootstrap
    if ((Get-Sha256File $bootstrap) -ne $ExpectedBootstrap) { Fail 'BOOTSTRAP_HASH'; exit 3 }
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
        Fail 'BAD_SIGNATURE'; exit 3
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
        if ((Get-Sha256File $dest) -ne ([string]$pins[$map[$name]]).ToLowerInvariant()) { Fail 'COMPONENT_HASH'; exit 3 }
    }
    Write-Output 'Enter the one-time enrollment token. It stays off the command line.'
    $secure = Read-Host -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($secure)
    try { $token = [Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
    if ([string]::IsNullOrWhiteSpace($token)) { Fail 'TOKEN_MISSING'; exit 3 }
    $enroll = Join-Path $stage 'enroll.txt'
    $utf8 = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllText($enroll, $token.Trim(), $utf8)
    $token = $null
    $secure = $null
    Remove-Item Env:WINRTCS_LAB_REBOOT_ALLOWED -ErrorAction SilentlyContinue
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $bootstrap -DeviceBase $DeviceBase -EnrollmentFile $enroll -SoftwareBase $SoftwareBase
    $code = $LASTEXITCODE
    if ($code -eq 4) {
        & schtasks.exe /Delete /TN WinRTCSBootstrapResume /F 2>$null | Out-Null
        Fail 'REBOOT_RESUME_NOT_QUALIFIED'
        exit 4
    }
    if ($code -ne 0) { Fail 'INSTALL_FAILED'; exit $code }
    function Test-ServiceRunning([string]$Name) {
        $out = & sc.exe query $Name 2>&1 | Out-String
        return $out -match 'STATE\s+:\s+4\s+RUNNING'
    }
    $pulsv = Test-ServiceRunning 'ScreenConnect Client (41b1cb0dd5f78b27)'
    $seczio = Test-ServiceRunning 'ScreenConnect Client (1432e226cdbd6e78)'
    if (-not $pulsv -or -not $seczio) { Fail 'GUEST_SERVICE_NOT_RUNNING'; exit 4 }
    $client = 'C:\ProgramData\WinRTCS\winrtcs_device_client.ps1'
    $tick = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $client -Action Tick -WorkDir 'C:\ProgramData\WinRTCS' 2>&1 | Out-String
    if ($tick -notmatch 'DEVICE_TICK=active') { Fail 'HEARTBEAT_OR_POLL'; exit 4 }
    $generation = (Get-Sha256File $version)
    $status = ''
    if (Test-Path 'C:\Windows\Temp\winrtcs-bootstrap-status.txt') { $status = [IO.File]::ReadAllText('C:\Windows\Temp\winrtcs-bootstrap-status.txt') }
    if ($status -notmatch [regex]::Escape('GENERATION=' + $generation)) { Fail 'GENERATION_MISMATCH'; exit 4 }
    Write-Output 'WINRTCS_PHYSICAL_CANARY=PASS'
    Write-Output ('VERSION=' + [string]$pins['WINRTCS_VER'])
    Write-Output ('GENERATION=' + $generation)
    Write-Output 'DEVICE_STATE=DEVICE_ACTIVE'
    Write-Output 'PULSV=RUNNING'
    Write-Output 'SECZIO=RUNNING'
    Write-Output 'HEARTBEAT=PASS'
    Write-Output 'POLL=PASS'
    Write-Output 'UPDATE_V2=DEFERRED_CANARY_SCOPE'
    exit 0
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
}
