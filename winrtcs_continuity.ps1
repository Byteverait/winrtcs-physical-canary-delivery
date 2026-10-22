# WINRTCS_CONTINUITY
# Local task verification and a bounded Agent relaunch.
# No control-route authentication, command execution, credential minting, or enrollment.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'VerifyTask', 'Watch')]
    [string]$Action
)

$ErrorActionPreference = 'Stop'
$Zd = 'C:\ProgramData\WinRTCS'
$Cache = 'C:\ProgramData\Microsoft\WinRTCS\cache'
$AgentTask = 'Agent'
$WatchTask = 'Continuity'
$TaskPath = '\Microsoft\Windows\WinRTCS\'
$RunArgument = '/c C:\ProgramData\WinRTCS\winrtcs_run.cmd'
$ExpectedCommit = '492d9401bddb096ae78d7012ac3b09db79e5f9461c3a66405c3f9c3693b7729a'
$ExpectedModulus = '8DqwRNmYBSaROA/XTrOje0YqHIGfKhoaUKkeb1ds4BZRAJDCDu1l5ctBRfR+neHIApUaxl3RMIuUez4BnAmbTjBJ4YrJJqKW4uCGRS42kfFaGXUM9VJCxEcki8md2Fjzc7FlH3lutDoi2dPel46ntrWxGhwWQ8TME3MKdulZ7xzCbjXvkxrLMkWZ74w0oCvYYKGlS1ghYk4mxnZGXyFtXCSTGyEOL20INskjdYkYhlHMvj+xjJV0S55GNh3miFjBZmOROVXljTH3SezV/fxXmc2jShL5RH2jjkre4pzlP3HewwU0oelymG4yk0MYjoYyJD8WvSBf6C0bxESHUmCv7Q=='
$WatchExecute = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$verifier = @'
$ErrorActionPreference = 'Stop'
$cache = 'C:\ProgramData\Microsoft\WinRTCS\cache'
$zd = 'C:\ProgramData\WinRTCS'
$expected = '__COMMIT__'
$modulus = '__MODULUS__'
$commit = Join-Path $cache 'winrtcs_gen_commit.ps1'
$version = Join-Path $cache 'winrtcs.version'
$sig = Join-Path $cache 'winrtcs.version.sig'
function Write-Reject([string]$why) {
    $unix = [string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $text = "task=preexec`r`nwatchdog=rejected`r`ntick_unix=$unix`r`nfailure=$why`r`n"
    [IO.File]::WriteAllText((Join-Path $zd 'continuity-status.txt'), $text, (New-Object Text.UTF8Encoding $false))
    exit 0
}
if (-not (Test-Path -LiteralPath $commit)) { Write-Reject 'commit-missing' }
$sha = [Security.Cryptography.SHA256]::Create()
$stream = [IO.File]::Open($commit, 'Open', 'Read', 'Read')
try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
finally { $stream.Dispose(); $sha.Dispose() }
$signed = $false
if (Test-Path -LiteralPath $sig) {
    if (-not (Test-Path -LiteralPath $version)) { Write-Reject 'bad-sig' }
    $sigText = [IO.File]::ReadAllText($sig)
    $sigB64 = [regex]::Match($sigText, '(?m)^sig=([A-Za-z0-9+/=]+)\s*$').Groups[1].Value
    if (-not $sigB64) { Write-Reject 'bad-sig' }
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $params = New-Object System.Security.Cryptography.RSAParameters
    $params.Modulus = [Convert]::FromBase64String($modulus)
    $params.Exponent = [Convert]::FromBase64String('AQAB')
    $rsa.ImportParameters($params)
    $ok = $false
    try { $ok = $rsa.VerifyData([IO.File]::ReadAllBytes($version), 'SHA256', [Convert]::FromBase64String($sigB64)) } catch { $ok = $false }
    if (-not $ok) { Write-Reject 'bad-sig' }
    $signed = $true
}
if ($hash -ne $expected) { Write-Reject 'commit-hash' }
if ($signed) {
    $pin = ''
    foreach ($line in [IO.File]::ReadAllLines($version)) {
        if ($line.StartsWith('COMMIT_SHA256=')) { $pin = $line.Substring(14).Trim().ToLowerInvariant() }
    }
    if ($pin -ne $hash) { Write-Reject 'commit-hash' }
}
& 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $commit -LaunchWatchdog
exit $LASTEXITCODE
'@
$verifier = $verifier.Replace('__COMMIT__', $ExpectedCommit).Replace('__MODULUS__', $ExpectedModulus)
$WatchArgument = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($verifier))
$agentVerifier = @'
$ErrorActionPreference = 'Stop'
$zd = 'C:\ProgramData\WinRTCS'
$expectRun = '__RUN__'
$expectAgent = '__AGENT__'
$expectCont = '__CONT__'
$expectClient = '__CLIENT__'
$expectKeeper = '__KEEPER__'
$modulus = '__MOD__'
$run = Join-Path $zd 'winrtcs_run.cmd'
$agent = Join-Path $zd 'winrtcs_agent.cmd'
$script = Join-Path $zd 'winrtcs_continuity.ps1'
$client = Join-Path $zd 'winrtcs_device_client.ps1'
$keeper = Join-Path $zd 'winrtcs_keeper.ps1'
$version = Join-Path $zd 'winrtcs.version'
$cacheVersion = 'C:\ProgramData\Microsoft\WinRTCS\cache\winrtcs.version'
$sig = Join-Path $zd 'winrtcs.version.sig'
$cacheSig = 'C:\ProgramData\Microsoft\WinRTCS\cache\winrtcs.version.sig'
function Write-Reject([string]$why) {
    $unix = [string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $text = "task=continuity-preexec`r`nwatchdog=rejected`r`ntick_unix=$unix`r`nfailure=$why`r`n"
    [IO.File]::WriteAllText((Join-Path $zd 'continuity-status.txt'), $text, (New-Object Text.UTF8Encoding $false))
    exit 0
}
function Get-ShaHex([string]$path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::Open($path, 'Open', 'Read', 'Read')
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}
function Assert-File([string]$path, [string]$expected, [string]$missing, [string]$wrong) {
    if (-not (Test-Path -LiteralPath $path)) { Write-Reject $missing }
    if ((Get-ShaHex $path) -ne $expected) { Write-Reject $wrong }
}
$sigPath = ''
$versionPath = ''
if (Test-Path -LiteralPath $sig) { $sigPath = $sig; $versionPath = $version }
elseif (Test-Path -LiteralPath $cacheSig) { $sigPath = $cacheSig; $versionPath = $cacheVersion }
if ($sigPath) {
    if (-not (Test-Path -LiteralPath $versionPath)) { Write-Reject 'bad-sig' }
    $sigText = [IO.File]::ReadAllText($sigPath)
    $sigB64 = [regex]::Match($sigText, '(?m)^sig=([A-Za-z0-9+/=]+)\s*$').Groups[1].Value
    if (-not $sigB64) { Write-Reject 'bad-sig' }
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $params = New-Object System.Security.Cryptography.RSAParameters
    $params.Modulus = [Convert]::FromBase64String($modulus)
    $params.Exponent = [Convert]::FromBase64String('AQAB')
    $rsa.ImportParameters($params)
    $ok = $false
    try { $ok = $rsa.VerifyData([IO.File]::ReadAllBytes($versionPath), 'SHA256', [Convert]::FromBase64String($sigB64)) } catch { $ok = $false }
    if (-not $ok) { Write-Reject 'bad-sig' }
    $pins = @{}
    foreach ($line in [IO.File]::ReadAllLines($versionPath)) {
        foreach ($key in @('RUN_SHA256','AGENT_SHA256','CONTINUITY_SHA256','CLIENT_SHA256','KEEPER_SHA256')) {
            $prefix = $key + '='
            if ($line.StartsWith($prefix)) { $pins[$key] = $line.Substring($prefix.Length).Trim().ToLowerInvariant() }
        }
    }
    if ($pins['RUN_SHA256'] -ne $expectRun -or $pins['AGENT_SHA256'] -ne $expectAgent -or $pins['CONTINUITY_SHA256'] -ne $expectCont -or $pins['CLIENT_SHA256'] -ne $expectClient -or $pins['KEEPER_SHA256'] -ne $expectKeeper) { Write-Reject 'bad-sig' }
}
Assert-File $run $expectRun 'run-missing' 'run-hash'
Assert-File $agent $expectAgent 'agent-missing' 'agent-hash'
Assert-File $script $expectCont 'continuity-missing' 'continuity-hash'
Assert-File $client $expectClient 'client-missing' 'client-hash'
Assert-File $keeper $expectKeeper 'keeper-missing' 'keeper-hash'
$ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -Action Prepare
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& 'C:\Windows\System32\cmd.exe' /c $run
$rc = $LASTEXITCODE
if ($rc -eq 0) {
    & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -Action VerifyTask
}
exit $rc
'@
$StaleSeconds = 180
$CooldownSeconds = 120
$StuckSeconds = 600

function Get-FileSha([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Get-Pin([string]$Key) {
    foreach ($root in @($Zd, $Cache)) {
        $path = Join-Path $root 'winrtcs.version'
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($line in [IO.File]::ReadAllLines($path)) {
            $prefix = $Key + '='
            if ($line.StartsWith($prefix)) { return $line.Substring($prefix.Length).Trim().ToLowerInvariant() }
        }
    }
    return ''
}

function Update-Diag([hashtable]$Values) {
    $path = Join-Path $Zd 'continuity-status.txt'
    $map = @{ task = 'none'; watchdog = 'none'; tick_unix = '0'; failure = 'none' }
    if (Test-Path -LiteralPath $path) {
        foreach ($line in [IO.File]::ReadAllLines($path)) {
            $pair = $line.Split('=', 2)
            if ($pair.Length -eq 2 -and $map.ContainsKey($pair[0])) { $map[$pair[0]] = $pair[1] }
        }
    }
    foreach ($key in @($Values.Keys)) { $map[$key] = [string]$Values[$key] }
    $text = "task=$($map.task)`r`nwatchdog=$($map.watchdog)`r`ntick_unix=$($map.tick_unix)`r`nfailure=$($map.failure)`r`n"
    $utf8 = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllText($path, $text, $utf8)
}

function Get-MarkerUnix {
    $path = Join-Path $Zd 'continuity.txt'
    if (-not (Test-Path -LiteralPath $path)) { return 0 }
    foreach ($line in [IO.File]::ReadAllLines($path)) {
        if ($line.StartsWith('unix=')) {
            $value = 0L
            [void][int64]::TryParse($line.Substring(5).Trim(), [ref]$value)
            return $value
        }
    }
    return 0
}

function New-ContinuitySettings {
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    $settings.ExecutionTimeLimit = 'PT15M'
    return $settings
}

function New-MinuteTrigger([int]$Minutes) {
    $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(-1)) -RepetitionInterval (New-TimeSpan -Minutes $Minutes) -RepetitionDuration (New-TimeSpan -Days 3650)
    $trigger.Repetition.StopAtDurationEnd = $false
    return $trigger
}

function Install-ContinuityTask([string]$Name, [string]$Argument, [int]$Minutes, [string]$Execute = 'cmd.exe') {
    try {
        $action = New-ScheduledTaskAction -Execute $Execute -Argument $Argument
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $Name -TaskPath $TaskPath -Action $action -Trigger (New-MinuteTrigger $Minutes) -Settings (New-ContinuitySettings) -Principal $principal -Force | Out-Null
    } catch {
        if ($Execute -notmatch 'cmd\.exe$') { throw }
        $taskName = $TaskPath + $Name
        $command = 'cmd.exe ' + $Argument
        & schtasks.exe /Create /TN $taskName /TR $command /SC MINUTE /MO $Minutes /RU SYSTEM /RL HIGHEST /F | Out-Null
        if ($LASTEXITCODE -ne 0) { throw }
    }
}

function Test-ContinuityTask([string]$Name, [string]$Argument, [string]$Interval, [string]$Execute = 'cmd.exe') {
    $task = Get-ScheduledTask -TaskName $Name -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if (-not $task) { return 'missing' }
    if ([string]$task.State -eq 'Disabled') { return 'disabled' }
    $action = $task.Actions | Select-Object -First 1
    if (-not $action) { return 'bad-action' }
    $leaf = [IO.Path]::GetFileName($Execute)
    if ([string]$action.Execute -notmatch ([regex]::Escape($leaf) + '$')) { return 'bad-action' }
    if ([string]$action.Arguments -ne $Argument) { return 'bad-action' }
    $trigger = $task.Triggers | Select-Object -First 1
    if (-not $trigger -or -not $trigger.Enabled) { return 'bad-trigger' }
    if ([string]$trigger.Repetition.Interval -ne $Interval) { return 'bad-trigger' }
    $principal = $task.Principal
    if (-not $principal) { return 'bad-principal' }
    $user = [string]$principal.UserId
    $systemUser = @('S-1-5-18', 'SYSTEM', 'NT AUTHORITY\SYSTEM') -contains $user
    if (-not $systemUser -or [string]$principal.LogonType -ne 'ServiceAccount' -or [string]$principal.RunLevel -ne 'Highest') { return 'bad-principal' }
    return 'ok'
}

function Repair-ContinuityTask([string]$Name, [string]$Argument, [int]$Minutes, [string]$Interval, [string]$Execute = 'cmd.exe') {
    $state = Test-ContinuityTask $Name $Argument $Interval $Execute
    if ($state -eq 'ok') { return 'ok' }
    if ($state -eq 'disabled') {
        Enable-ScheduledTask -TaskName $Name -TaskPath $TaskPath | Out-Null
        $state = Test-ContinuityTask $Name $Argument $Interval $Execute
        if ($state -eq 'ok') { return 'repaired' }
    }
    Install-ContinuityTask $Name $Argument $Minutes $Execute
    return 'repaired'
}

function Restore-DeviceCfg {
    $pin = Get-Pin 'CONFIG_SHA256'
    if ($pin.Length -ne 64) { return 'cfg-unpinned' }
    $live = Join-Path $Zd 'winrtcs_device.cfg'
    $cached = Join-Path $Cache 'winrtcs_device.cfg'
    if ((Test-Path -LiteralPath $live) -and (Get-FileSha $live) -eq $pin) { return 'cfg-ok' }
    if ((Test-Path -LiteralPath $cached) -and (Get-FileSha $cached) -eq $pin) {
        [IO.File]::Copy($cached, $live, $true)
        if ((Get-FileSha $live) -eq $pin) { return 'cfg-restored' }
    }
    return 'cfg-missing'
}

function Test-ComponentHash([string]$FileName, [string]$PinKey) {
    $pin = Get-Pin $PinKey
    $path = Join-Path $Zd $FileName
    if ($pin.Length -ne 64 -or -not (Test-Path -LiteralPath $path)) { return $false }
    return (Get-FileSha $path) -eq $pin
}

function Test-ManifestSignature([string]$VersionPath, [string]$SigPath) {
    if (-not (Test-Path -LiteralPath $VersionPath) -or -not (Test-Path -LiteralPath $SigPath)) { return $false }
    $sigText = [IO.File]::ReadAllText($SigPath)
    $sigB64 = [regex]::Match($sigText, '(?m)^sig=([A-Za-z0-9+/=]+)\s*$').Groups[1].Value
    if (-not $sigB64) { return $false }
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $params = New-Object System.Security.Cryptography.RSAParameters
    $params.Modulus = [Convert]::FromBase64String($ExpectedModulus)
    $params.Exponent = [Convert]::FromBase64String('AQAB')
    $rsa.ImportParameters($params)
    try {
        return [bool]$rsa.VerifyData([IO.File]::ReadAllBytes($VersionPath), 'SHA256', [Convert]::FromBase64String($sigB64))
    } catch {
        return $false
    }
}

function Get-AgentLaunchArgument {
    $versionPath = ''
    foreach ($root in @($Cache, $Zd)) {
        $version = Join-Path $root 'winrtcs.version'
        $sig = Join-Path $root 'winrtcs.version.sig'
        if (-not (Test-Path -LiteralPath $version)) { continue }
        if (Test-Path -LiteralPath $sig) {
            if (-not (Test-ManifestSignature $version $sig)) { return '' }
            $versionPath = $version
            break
        }
        if (-not $versionPath) { $versionPath = $version }
    }
    if (-not $versionPath) { return '' }
    $pins = @{}
    foreach ($line in [IO.File]::ReadAllLines($versionPath)) {
        foreach ($key in @('RUN_SHA256', 'AGENT_SHA256', 'CONTINUITY_SHA256', 'CLIENT_SHA256', 'KEEPER_SHA256')) {
            $prefix = $key + '='
            if ($line.StartsWith($prefix)) { $pins[$key] = $line.Substring($prefix.Length).Trim().ToLowerInvariant() }
        }
    }
    $files = @{
        RUN_SHA256 = 'winrtcs_run.cmd'
        AGENT_SHA256 = 'winrtcs_agent.cmd'
        CONTINUITY_SHA256 = 'winrtcs_continuity.ps1'
        CLIENT_SHA256 = 'winrtcs_device_client.ps1'
        KEEPER_SHA256 = 'winrtcs_keeper.ps1'
    }
    foreach ($key in @($files.Keys)) {
        $pin = [string]$pins[$key]
        $live = Join-Path $Zd $files[$key]
        if ($pin.Length -ne 64 -or -not (Test-Path -LiteralPath $live) -or (Get-FileSha $live) -ne $pin) { return '' }
    }
    $body = $agentVerifier.Replace('__RUN__', $pins['RUN_SHA256']).Replace('__AGENT__', $pins['AGENT_SHA256']).Replace('__CONT__', $pins['CONTINUITY_SHA256']).Replace('__CLIENT__', $pins['CLIENT_SHA256']).Replace('__KEEPER__', $pins['KEEPER_SHA256']).Replace('__MOD__', $ExpectedModulus)
    return '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
}

function Get-UnixNow {
    return [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
}

if ($Action -eq 'Prepare') {
    $cfg = Restore-DeviceCfg
    $watch = Repair-ContinuityTask $WatchTask $WatchArgument 5 'PT5M' $WatchExecute
    $failure = 'none'
    if ($cfg -eq 'cfg-missing' -or $cfg -eq 'cfg-unpinned') { $failure = $cfg }
    Update-Diag @{ watchdog = $watch; failure = $failure }
    if ($failure -ne 'none') { exit 4 }
    exit 0
}

if ($Action -eq 'VerifyTask') {
    $agentArgument = Get-AgentLaunchArgument
    if (-not $agentArgument) {
        Update-Diag @{ task = 'rejected'; failure = 'continuity-pin' }
        exit 4
    }
    $state = Repair-ContinuityTask $AgentTask $agentArgument 1 'PT1M' $WatchExecute
    $failure = 'none'
    $failPath = Join-Path $Zd 'continuity-failure.txt'
    if (Test-Path -LiteralPath $failPath) { $failure = ([IO.File]::ReadAllText($failPath)).Trim() }
    if ($failure.Length -gt 140) { $failure = $failure.Substring(0, 140) }
    Update-Diag @{ task = $state; tick_unix = (Get-MarkerUnix); failure = $failure }
    exit 0
}

if (-not (Test-ComponentHash 'winrtcs_agent.cmd' 'AGENT_SHA256') -or -not (Test-ComponentHash 'winrtcs_run.cmd' 'RUN_SHA256') -or -not (Test-ComponentHash 'winrtcs_keeper.ps1' 'KEEPER_SHA256')) {
    Update-Diag @{ watchdog = 'skipped-hash'; failure = 'hash-mismatch' }
    exit 0
}
$agentArgument = Get-AgentLaunchArgument
if (-not $agentArgument) {
    Update-Diag @{ watchdog = 'rejected'; failure = 'continuity-pin' }
    exit 0
}
$state = Repair-ContinuityTask $AgentTask $agentArgument 1 'PT1M' $WatchExecute
$now = Get-UnixNow
$marker = Get-MarkerUnix
$lastPath = Join-Path $Zd 'watchdog-last.txt'
$last = 0L
if (Test-Path -LiteralPath $lastPath) { [void][int64]::TryParse(([IO.File]::ReadAllText($lastPath)).Trim(), [ref]$last) }
$cooled = ($last -gt 0 -and ($now - $last) -lt $CooldownSeconds)
if ($state -eq 'repaired') {
    if ($cooled) {
        Update-Diag @{ task = $state; watchdog = 'skipped-cooldown'; tick_unix = $marker; failure = 'none' }
        exit 0
    }
    & schtasks.exe /Run /TN '\Microsoft\Windows\WinRTCS\Agent' | Out-Null
    [IO.File]::WriteAllText($lastPath, ([string]$now), (New-Object Text.UTF8Encoding $false))
    Update-Diag @{ task = $state; watchdog = 'started'; tick_unix = $marker; failure = 'none' }
    exit 0
}
if ($marker -gt 0 -and ($now - $marker) -lt $StaleSeconds) {
    Update-Diag @{ task = 'ok'; watchdog = 'skipped-fresh'; tick_unix = $marker; failure = 'none' }
    exit 0
}
if ($cooled) {
    Update-Diag @{ task = 'ok'; watchdog = 'skipped-cooldown'; tick_unix = $marker; failure = 'none' }
    exit 0
}
$task = Get-ScheduledTask -TaskName $AgentTask -TaskPath $TaskPath -ErrorAction SilentlyContinue
$info = Get-ScheduledTaskInfo -TaskName $AgentTask -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($task -and [string]$task.State -eq 'Running' -and $info -and $info.LastRunTime) {
    $age = ($now - [int64]([DateTimeOffset]$info.LastRunTime).ToUnixTimeSeconds())
    if ($age -ge 0 -and $age -lt $StuckSeconds) {
        Update-Diag @{ task = 'ok'; watchdog = 'skipped-running'; tick_unix = $marker; failure = 'none' }
        exit 0
    }
    & schtasks.exe /End /TN '\Microsoft\Windows\WinRTCS\Agent' | Out-Null
    & schtasks.exe /Run /TN '\Microsoft\Windows\WinRTCS\Agent' | Out-Null
    [IO.File]::WriteAllText($lastPath, ([string]$now), (New-Object Text.UTF8Encoding $false))
    Update-Diag @{ task = 'ok'; watchdog = 'stuck-ended'; tick_unix = $marker; failure = 'none' }
    exit 0
}
& schtasks.exe /Run /TN '\Microsoft\Windows\WinRTCS\Agent' | Out-Null
[IO.File]::WriteAllText($lastPath, ([string]$now), (New-Object Text.UTF8Encoding $false))
Update-Diag @{ task = 'ok'; watchdog = 'started'; tick_unix = $marker; failure = 'none' }
exit 0
