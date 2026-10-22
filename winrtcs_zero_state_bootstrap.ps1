# One-time elevated zero-state enrollment for frozen generation 1.0.0.25.
# Endpoint files under steady-state-10025 stay byte-identical. This script is not that generation.
param(
    [Parameter(Mandatory = $true)][string]$DeviceBase,
    [Parameter(Mandatory = $true)][string]$EnrollmentFile,
    [Parameter(Mandatory = $true)][string]$SoftwareBase,
    [string]$StateDir = 'C:\ProgramData\WinRTCS'
)
$ErrorActionPreference = 'Stop'
foreach ($name in @('WINRTCS_KEEPER_SELFTEST','WINRTCS_MSI_STUB_EXIT','WINRTCS_KEEPER_SELFTEST_NONCE')) {
    Remove-Item -Path ('Env:\' + $name) -ErrorAction SilentlyContinue
}
function Write-Status([string]$Line) {
    Write-Output $Line
    $statusPath = 'C:\Windows\Temp\winrtcs-bootstrap-status.txt'
    $utf8Status = New-Object Text.UTF8Encoding $false
    $stream = [IO.File]::Open($statusPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $bytes = $utf8Status.GetBytes($Line + "`r`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    } finally { $stream.Dispose() }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Status 'PRECHECK=admin-required'
    exit 2
}
if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Status 'PRECHECK=architecture'
    exit 2
}
if ($DeviceBase -notmatch '\Ahttps://[A-Za-z0-9.-]+(?::[0-9]{1,5})?\z') {
    Write-Status 'PRECHECK=device-base'
    exit 2
}
if ($null -ne [Net.ServicePointManager]::ServerCertificateValidationCallback) {
    Write-Status 'PRECHECK=tls-callback'
    exit 2
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::CheckCertificateRevocationList = $true
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
& icacls.exe $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
$identityPath = Join-Path $StateDir 'identity.json'
$keyPath = Join-Path $StateDir 'key.json'
$utf8 = New-Object Text.UTF8Encoding $false
if (Test-Path -LiteralPath $identityPath) {
    $parsed = [IO.File]::ReadAllText($identityPath) | ConvertFrom-Json
    $mid = ([string]$parsed.mid).Trim().ToLowerInvariant()
    $displayHost = [string]$parsed.host
    $currentName = ([string]$env:COMPUTERNAME).Trim().ToUpperInvariant()
    if ($currentName -and $currentName -cne $displayHost) { Write-Status 'HOSTNAME_CHANGE=kept-mid' }
} else {
    $rawGuid = [string](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    $mid = $rawGuid.Trim().ToLowerInvariant()
    $displayHost = ([string]$env:COMPUTERNAME).Trim().ToUpperInvariant()
    if ($displayHost -notmatch '\A[A-Z0-9_-]{1,63}\z') {
        Write-Status 'IDENTITY=hostname'
        exit 2
    }
    [IO.File]::WriteAllText($identityPath, (@{ host = $displayHost; mid = $mid } | ConvertTo-Json -Compress), $utf8)
}
if ($mid -notmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z') {
    Write-Status 'IDENTITY=machineguid'
    exit 2
}
$currentGuid = ([string](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid).Trim().ToLowerInvariant()
if ($currentGuid -cne $mid) {
    Write-Status 'IDENTITY=machineguid-changed'
    exit 2
}
if (Test-Path -LiteralPath $keyPath) {
    $material = [IO.File]::ReadAllText($keyPath) | ConvertFrom-Json
} else {
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
        [IO.File]::WriteAllText($keyPath, ($material | ConvertTo-Json -Compress), $utf8)
    } finally { $rsa.Dispose() }
}
function Join-Bytes([byte[]]$Left, [byte[]]$Right) {
    $all = New-Object byte[] ($Left.Length + $Right.Length)
    [Buffer]::BlockCopy($Left, 0, $all, 0, $Left.Length)
    [Buffer]::BlockCopy($Right, 0, $all, $Left.Length, $Right.Length)
    return ,$all
}
function Convert-Der([byte]$Tag, [byte[]]$Body) {
    if ($Body.Length -lt 128) { $length = [byte[]]@([byte]$Body.Length) }
    else {
        $rest = New-Object System.Collections.Generic.List[byte]
        $value = $Body.Length
        while ($value -gt 0) { $rest.Insert(0, [byte]($value -band 255)); $value = [int][math]::Floor($value / 256) }
        $length = New-Object byte[] ($rest.Count + 1)
        $length[0] = [byte](0x80 -bor $rest.Count)
        for ($i = 0; $i -lt $rest.Count; $i++) { $length[$i + 1] = $rest[$i] }
    }
    $tagged = New-Object byte[] (1 + $length.Length + $Body.Length)
    $tagged[0] = $Tag
    [Buffer]::BlockCopy($length, 0, $tagged, 1, $length.Length)
    [Buffer]::BlockCopy($Body, 0, $tagged, 1 + $length.Length, $Body.Length)
    return ,$tagged
}
function Convert-RsaSpki([byte[]]$Modulus, [byte[]]$Exponent) {
    if (($Modulus[0] -band 0x80) -ne 0) { $Modulus = Join-Bytes ([byte[]]@(0)) $Modulus }
    if (($Exponent[0] -band 0x80) -ne 0) { $Exponent = Join-Bytes ([byte[]]@(0)) $Exponent }
    $pub = Convert-Der 0x30 (Join-Bytes (Convert-Der 0x02 $Modulus) (Convert-Der 0x02 $Exponent))
    $bit = Convert-Der 0x03 (Join-Bytes ([byte[]]@(0)) $pub)
    $alg = [byte[]](0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00)
    return Convert-Der 0x30 (Join-Bytes $alg $bit)
}
$der = Convert-RsaSpki ([Convert]::FromBase64String([string]$material.modulus)) ([Convert]::FromBase64String([string]$material.exponent))
$pemBody = [Convert]::ToBase64String($der, 'InsertLineBreaks')
$pem = "-----BEGIN PUBLIC KEY-----`n$pemBody`n-----END PUBLIC KEY-----`n"
$token = ([IO.File]::ReadAllText($EnrollmentFile)).Trim()
function Invoke-JsonPost([string]$Path, [string]$Json, [int]$Attempts) {
    for ($try = 1; $try -le $Attempts; $try++) {
        $request = [Net.HttpWebRequest]::Create([Uri]($DeviceBase + $Path))
        $request.Method = 'POST'
        $request.Timeout = 20000
        $request.AllowAutoRedirect = $false
        $request.ContentType = 'application/json'
        $bytes = [Text.Encoding]::ASCII.GetBytes($Json)
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Close() }
        try {
            $response = $request.GetResponse()
            try {
                $reader = New-Object IO.StreamReader($response.GetResponseStream())
                try { return $reader.ReadToEnd() } finally { $reader.Close() }
            } finally { $response.Close() }
        } catch [Net.WebException] {
            if ($try -ge $Attempts) {
                Write-Status 'REGISTER=denied'
                exit 3
            }
        }
    }
}
if ($SoftwareBase -notmatch '\Ahttps://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~/-]*)?\z') {
    Write-Status 'PRECHECK=software-base'
    exit 2
}
$script:GenerationModulus = '8DqwRNmYBSaROA/XTrOje0YqHIGfKhoaUKkeb1ds4BZRAJDCDu1l5ctBRfR+neHIApUaxl3RMIuUez4BnAmbTjBJ4YrJJqKW4uCGRS42kfFaGXUM9VJCxEcki8md2Fjzc7FlH3lutDoi2dPel46ntrWxGhwWQ8TME3MKdulZ7xzCbjXvkxrLMkWZ74w0oCvYYKGlS1ghYk4mxnZGXyFtXCSTGyEOL20INskjdYkYhlHMvj+xjJV0S55GNh3miFjBZmOROVXljTH3SezV/fxXmc2jShL5RH2jjkre4pzlP3HewwU0oelymG4yk0MYjoYyJD8WvSBf6C0bxESHUmCv7Q=='
$script:PackageNames = @(
    'winrtcs_agent.cmd','winrtcs_guard.cmd','winrtcs_sentinel.cmd','winrtcs_run.cmd',
    'winrtcs_gen_commit.ps1','winrtcs_device_client.ps1','winrtcs_device.cfg',
    'winrtcs_continuity.ps1','winrtcs_watchdog.cmd','winrtcs_wdgate.cmd',
    'winrtcs_keeper.ps1'
)
$script:PinKeys = @{
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
function Get-Sha256File([string]$Path) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try { return ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $hasher.Dispose() }
}
function Receive-Software([string]$Name, [string]$Dest) {
    $request = [Net.HttpWebRequest]::Create([Uri]($SoftwareBase.TrimEnd('/') + '/' + $Name))
    $request.Method = 'GET'
    $request.Timeout = 20000
    $request.AllowAutoRedirect = $false
    $response = $request.GetResponse()
    try {
        $out = [IO.File]::Create($Dest)
        try { $response.GetResponseStream().CopyTo($out) } finally { $out.Close() }
    } finally { $response.Close() }
}
$stage = Join-Path $env:TEMP 'winrtcs-stage-once'
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
    Receive-Software 'winrtcs.version' (Join-Path $stage 'winrtcs.version')
    Receive-Software 'winrtcs.version.sig' (Join-Path $stage 'winrtcs.version.sig')
} catch {
    Write-Status 'INSTALL_BLOCKED=software-download'
    exit 3
}
$sigText = [IO.File]::ReadAllText((Join-Path $stage 'winrtcs.version.sig'))
$sigB64 = [regex]::Match($sigText, '(?m)^sig=([A-Za-z0-9+/=]+)\s*$').Groups[1].Value
$publisher = New-Object Security.Cryptography.RSACryptoServiceProvider
$params = New-Object Security.Cryptography.RSAParameters
$params.Modulus = [Convert]::FromBase64String($script:GenerationModulus)
$params.Exponent = [Convert]::FromBase64String('AQAB')
$publisher.ImportParameters($params)
$versionBytes = [IO.File]::ReadAllBytes((Join-Path $stage 'winrtcs.version'))
if (-not $sigB64 -or -not $publisher.VerifyData($versionBytes, 'SHA256', [Convert]::FromBase64String($sigB64))) {
    Write-Status 'INSTALL_BLOCKED=bad-signature'
    exit 3
}
$pins = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $stage 'winrtcs.version'))) {
    $pair = $line.Split('=', 2)
    if ($pair.Length -eq 2) { $pins[$pair[0].Trim()] = $pair[1].Trim() }
}
$build = 0
[void][int]::TryParse([string]$pins['BUILD_TS'], [ref]$build)
if ([string]$pins['WINRTCS_VER'] -ne '1.0.0.27' -or $build -le 1792670187) {
    Write-Status 'INSTALL_BLOCKED=manifest-schema'
    exit 3
}
if (-not (Test-Path -LiteralPath (Join-Path $stage 'winrtcs.version')) -or -not (Test-Path -LiteralPath (Join-Path $stage 'winrtcs.version.sig'))) {
    Write-Status 'INSTALL_BLOCKED=missing-manifest'
    exit 3
}
foreach ($name in $script:PackageNames) {
    try { Receive-Software $name (Join-Path $stage $name) } catch {
        Write-Status 'INSTALL_BLOCKED=software-download'
        exit 3
    }
    $expected = [string]$pins[$script:PinKeys[$name]]
    if ((Get-Sha256File (Join-Path $stage $name)) -ne $expected.ToLowerInvariant()) {
        Write-Status 'INSTALL_BLOCKED=bad-hash'
        exit 3
    }
}
$versionHash = Get-Sha256File (Join-Path $stage 'winrtcs.version')
$challenge = Invoke-JsonPost '/device/control/bootstrap/challenge' (@{ token = $token } | ConvertTo-Json -Compress) 1 | ConvertFrom-Json
if ([string]$challenge.approved_generation -ne $versionHash) {
    Write-Status 'INSTALL_BLOCKED=generation-mismatch'
    exit 3
}
$sha = [Security.Cryptography.SHA256]::Create()
try { $keyfp = ([BitConverter]::ToString($sha.ComputeHash($der))).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
$message = "WINRTCS_BOOTSTRAP_PROOF_V1`n$($challenge.token_id)`n$($challenge.challenge_id)`n$($challenge.nonce)`n$displayHost`n$mid`n$keyfp`n"
$signer = [Security.Cryptography.RSA]::Create()
try {
    $full = New-Object Security.Cryptography.RSAParameters
    foreach ($name in @('Modulus','Exponent','D','P','Q','DP','DQ','InverseQ')) {
    $full.$name = [Convert]::FromBase64String([string]$material.($name.ToLowerInvariant()))
    }
    $signer.ImportParameters($full)
    $signature = [Convert]::ToBase64String(
        $signer.SignData([Text.Encoding]::ASCII.GetBytes($message), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    )
} finally { $signer.Dispose() }
$registerBody = @{
    token = $token
    token_id = [string]$challenge.token_id
    host = $displayHost
    mid = $mid
    public_pem = $pem
    challenge_id = [string]$challenge.challenge_id
    nonce = [string]$challenge.nonce
    signature = $signature
} | ConvertTo-Json -Compress
$result = Invoke-JsonPost '/device/control/bootstrap/register' $registerBody 2 | ConvertFrom-Json
$record = @{ host = [string]$result.host; mid = [string]$result.mid; keyfp = [string]$result.keyfp; epoch = 1; generation = [string]$result.generation }
[IO.File]::WriteAllText($identityPath, ($record | ConvertTo-Json -Compress), $utf8)
foreach ($path in @($identityPath, $keyPath)) {
    & icacls.exe $path /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
}
if ([string]$result.keyfp -ne $keyfp) {
    Write-Status 'REGISTER=committed'
    Write-Status 'INSTALL_BLOCKED=principal-mismatch'
    exit 3
}
$fpPath = Join-Path $StateDir 'public-fp.txt'
[IO.File]::WriteAllText($fpPath, $keyfp, $utf8)
& icacls.exe $fpPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
Write-Status 'PRINCIPAL=ok'
Write-Status 'REGISTER=ok'
Write-Status ('MODE=' + [string]$result.mode)
if ([string]$result.generation -ne $versionHash) {
    Write-Status 'INSTALL_BLOCKED=generation-mismatch'
    exit 3
}
$cache = 'C:\ProgramData\Microsoft\WinRTCS\cache'
New-Item -ItemType Directory -Force -Path $cache | Out-Null
foreach ($name in (@('winrtcs.version','winrtcs.version.sig') + $script:PackageNames)) {
    Copy-Item -LiteralPath (Join-Path $stage $name) -Destination (Join-Path $cache $name) -Force
}
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $cache 'winrtcs_gen_commit.ps1') -Repair
if ($LASTEXITCODE -ne 0) {
    Write-Status 'INSTALL_BLOCKED=generation-commit'
    exit 4
}
$commitResult = ''
$resultPath = Join-Path $StateDir 'gen-commit-result.txt'
if (Test-Path -LiteralPath $resultPath) { $commitResult = ([IO.File]::ReadAllText($resultPath)).Trim() }
if ($commitResult -ne 'NEW_COMPLETE' -and $commitResult -ne 'IDEMPOTENT') {
    Write-Status 'INSTALL_BLOCKED=generation-commit'
    exit 4
}
$keeperScript = Join-Path $StateDir 'winrtcs_keeper.ps1'
if (-not (Test-Path -LiteralPath $keeperScript)) {
    Write-Status 'INSTALL_BLOCKED=keeper-script'
    exit 4
}
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $keeperScript -Action Ensure
if ($LASTEXITCODE -ne 0) {
    Write-Status 'INSTALL_BLOCKED=keeper-ensure'
    exit 4
}
$keeperMap = @{}
$keeperStatus = Join-Path $StateDir 'keeper-status.txt'
if (Test-Path -LiteralPath $keeperStatus) {
    foreach ($line in [IO.File]::ReadAllLines($keeperStatus)) {
        $pair = $line.Split('=', 2)
        if ($pair.Length -eq 2) { $keeperMap[$pair[0].Trim()] = $pair[1].Trim() }
    }
}
$resumePath = Join-Path $StateDir 'bootstrap-resume.txt'
$resumeTask = 'WinRTCSBootstrapResume'
if ([string]$keeperMap['KEEPER_INSTALL_REBOOT_REQUIRED'] -eq 'true') {
    $priorCount = 0
    if (Test-Path -LiteralPath $resumePath) {
        foreach ($line in [IO.File]::ReadAllLines($resumePath)) {
            $pair = $line.Split('=', 2)
            if ($pair.Length -eq 2 -and $pair[0].Trim() -eq 'COUNT') { $priorCount = [int]$pair[1].Trim() }
        }
    }
    if ($priorCount -ge 1) {
        & schtasks.exe /Delete /TN $resumeTask /F 2>$null | Out-Null
        Write-Status 'INSTALL_BLOCKED=reboot-loop'
        exit 4
    }
    $scriptCopy = Join-Path $StateDir 'winrtcs_zero_state_bootstrap.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $scriptCopy -Force
    [IO.File]::WriteAllText($resumePath, "PHASE=POST_KEEPER`r`nCOUNT=1`r`n")
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT1H</ExecutionTimeLimit></Settings>
  <Actions><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$scriptCopy" -DeviceBase "$DeviceBase" -EnrollmentFile "$EnrollmentFile" -SoftwareBase "$SoftwareBase"</Arguments></Exec></Actions>
</Task>
"@
    $taskFile = Join-Path $StateDir 'bootstrap-resume.xml'
    [IO.File]::WriteAllText($taskFile, $taskXml, (New-Object Text.UnicodeEncoding $false, $true))
    & schtasks.exe /Create /TN $resumeTask /XML $taskFile /F | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Status 'INSTALL_BLOCKED=resume-task'
        exit 4
    }
    Write-Status 'KEEPER_REBOOT=3010'
    Write-Status 'REBOOT_RESUME=armed'
    if ($env:WINRTCS_LAB_REBOOT_ALLOWED -eq '1') {
        & shutdown.exe /r /t 30 /c 'WinRTCS keeper reboot required' | Out-Null
        Write-Status 'REBOOT_RESUME=lab-reboot-requested'
    }
    exit 4
}
if (Test-Path -LiteralPath $resumePath) {
    & schtasks.exe /Delete /TN $resumeTask /F 2>$null | Out-Null
    Remove-Item -LiteralPath $resumePath -Force
    Remove-Item -LiteralPath (Join-Path $StateDir 'bootstrap-resume.xml') -Force -ErrorAction SilentlyContinue
    Write-Status 'REBOOT_RESUME=cleared'
}
if ([string]$keeperMap['KEEPER_HEALTH'] -ne 'HEALTHY') {
    Write-Status 'INSTALL_BLOCKED=keeper-not-healthy'
    exit 4
}
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $StateDir 'winrtcs_continuity.ps1') -Action Prepare
if ($LASTEXITCODE -ne 0) {
    Write-Status 'INSTALL_BLOCKED=task-create'
    exit 4
}
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $StateDir 'winrtcs_continuity.ps1') -Action Watch
Remove-Item -LiteralPath $EnrollmentFile -Force
$token = $null
Remove-Item -LiteralPath $stage -Recurse -Force
Write-Status 'INSTALL=ok'
Write-Status ('GENERATION=' + [string]$result.generation)
exit 0
