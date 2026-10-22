# WINRTCS_GEN_COMMIT
# One TxF transaction replaces the live set and the cache set.
# OPEN_EXISTING for a file that is already present. CREATE_NEW only for a
# file that is absent. CREATE_ALWAYS is not used.
# A cache manifest is not a committed generation until its component hashes match.
# A failed transaction rolls back. Readers keep the previous complete set.
$ErrorActionPreference = 'Stop'
$Floor = 1792000000
$ExpectedModulus = '8DqwRNmYBSaROA/XTrOje0YqHIGfKhoaUKkeb1ds4BZRAJDCDu1l5ctBRfR+neHIApUaxl3RMIuUez4BnAmbTjBJ4YrJJqKW4uCGRS42kfFaGXUM9VJCxEcki8md2Fjzc7FlH3lutDoi2dPel46ntrWxGhwWQ8TME3MKdulZ7xzCbjXvkxrLMkWZ74w0oCvYYKGlS1ghYk4mxnZGXyFtXCSTGyEOL20INskjdYkYhlHMvj+xjJV0S55GNh3miFjBZmOROVXljTH3SezV/fxXmc2jShL5RH2jjkre4pzlP3HewwU0oelymG4yk0MYjoYyJD8WvSBf6C0bxESHUmCv7Q=='
$zd = 'C:\ProgramData\WinRTCS'
$cache = 'C:\ProgramData\Microsoft\WinRTCS\cache'
$stage = Join-Path $cache 'stage'
$result = Join-Path $zd 'gen-commit-result.txt'
$names = @('winrtcs_agent.cmd','winrtcs_guard.cmd','winrtcs_sentinel.cmd','winrtcs_run.cmd','winrtcs_gen_commit.ps1','winrtcs_device_client.ps1','winrtcs_device.cfg','winrtcs_continuity.ps1','winrtcs_watchdog.cmd','winrtcs_wdgate.cmd','winrtcs_keeper.ps1')
$pinKeys = @{
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
$script:Txn = [IntPtr]::Zero
$script:Committed = $false

function Write-Result([string]$text) {
    Set-Content -LiteralPath $result -Value $text -Encoding ascii
}
function Fail([int]$code, [string]$why) {
    if (-not $script:Committed -and $script:Txn -ne [IntPtr]::Zero) {
        [GenTxn]::RollbackTransaction($script:Txn) | Out-Null
        [GenTxn]::CloseHandle($script:Txn) | Out-Null
        $script:Txn = [IntPtr]::Zero
    }
    Write-Result $why
    exit $code
}
function Get-Sha256([string]$path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::Open($path, 'Open', 'Read', 'Read')
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}
function Read-Pins([string]$path) {
    $map = @{}
    foreach ($line in [IO.File]::ReadAllLines($path)) {
        $pair = $line.Split('=', 2)
        if ($pair.Length -eq 2) { $map[$pair[0].Trim()] = $pair[1].Trim() }
    }
    return $map
}
function Test-Manifest([string]$versionPath, [string]$sigPath) {
    if (-not (Test-Path -LiteralPath $versionPath) -or -not (Test-Path -LiteralPath $sigPath)) { return $false }
    $sigText = [IO.File]::ReadAllText($sigPath)
    $sigB64 = [regex]::Match($sigText, '(?m)^sig=([A-Za-z0-9+/=]+)\s*$').Groups[1].Value
    if (-not $sigB64) { return $false }
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $params = New-Object System.Security.Cryptography.RSAParameters
    $params.Modulus = [Convert]::FromBase64String($ExpectedModulus)
    $params.Exponent = [Convert]::FromBase64String('AQAB')
    $rsa.ImportParameters($params)
    try { return $rsa.VerifyData([IO.File]::ReadAllBytes($versionPath), 'SHA256', [Convert]::FromBase64String($sigB64)) }
    catch { return $false }
}

if ($args -contains '-LaunchWatchdog') {
    $diag = Join-Path $zd 'continuity-status.txt'
    function Write-Gate([string]$watch, [string]$why) {
        $unix = [string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $text = "task=gate`r`nwatchdog=$watch`r`ntick_unix=$unix`r`nfailure=$why`r`n"
        [IO.File]::WriteAllText($diag, $text, (New-Object Text.UTF8Encoding $false))
    }
    $versionPath = Join-Path $cache 'winrtcs.version'
    $sigPath = Join-Path $cache 'winrtcs.version.sig'
    if (-not (Test-Path -LiteralPath $versionPath)) {
        Write-Gate 'rejected' 'manifest-missing'
        exit 0
    }
    $pins = Read-Pins $versionPath
    if ((Test-Path -LiteralPath $sigPath) -and -not (Test-Manifest $versionPath $sigPath)) {
        Write-Gate 'rejected' 'bad-sig'
        exit 0
    }
    function Test-Pinned([string]$fileName, [string]$pinKey) {
        $pin = ([string]$pins[$pinKey]).ToLowerInvariant()
        $cached = Join-Path $cache $fileName
        if ($pin.Length -ne 64 -or -not (Test-Path -LiteralPath $cached)) { return $false }
        return (Get-Sha256 $cached) -eq $pin
    }
    function Restore-Pinned([string]$fileName, [string]$pinKey) {
        if (-not (Test-Pinned $fileName $pinKey)) { return $false }
        $pin = ([string]$pins[$pinKey]).ToLowerInvariant()
        $live = Join-Path $zd $fileName
        if ((Test-Path -LiteralPath $live) -and (Get-Sha256 $live) -eq $pin) { return $true }
        [IO.File]::Copy((Join-Path $cache $fileName), $live, $true)
        return (Get-Sha256 $live) -eq $pin
    }
    if (-not (Test-Pinned 'winrtcs_wdgate.cmd' 'LAUNCHER_SHA256') -or -not (Test-Pinned 'winrtcs_watchdog.cmd' 'WATCHDOG_SHA256')) {
        Write-Gate 'rejected' 'unpinned'
        exit 0
    }
    $launcherPin = ([string]$pins['LAUNCHER_SHA256']).ToLowerInvariant()
    $watchPin = ([string]$pins['WATCHDOG_SHA256']).ToLowerInvariant()
    $liveLauncher = Join-Path $zd 'winrtcs_wdgate.cmd'
    $liveWatch = Join-Path $zd 'winrtcs_watchdog.cmd'
    $launcherMatch = (Test-Path -LiteralPath $liveLauncher) -and (Get-Sha256 $liveLauncher) -eq $launcherPin
    $watchMatch = (Test-Path -LiteralPath $liveWatch) -and (Get-Sha256 $liveWatch) -eq $watchPin
    if (-not $launcherMatch -or -not $watchMatch) {
        [void](Restore-Pinned 'winrtcs_wdgate.cmd' 'LAUNCHER_SHA256')
        [void](Restore-Pinned 'winrtcs_watchdog.cmd' 'WATCHDOG_SHA256')
        $why = $(if (-not $watchMatch) { 'hash-mismatch' } else { 'launcher-mismatch' })
        Write-Gate 'rejected' $why
        exit 0
    }
    $gate = Join-Path $cache 'winrtcs_wdgate.cmd'
    if ((Get-Sha256 $gate) -ne $launcherPin -or (Get-Sha256 $liveWatch) -ne $watchPin) {
        Write-Gate 'rejected' 'hash-mismatch'
        exit 0
    }
    & cmd.exe /c $gate
    exit $LASTEXITCODE
}

if (-not ('GenTxn' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class GenTxn {
    const uint GENERIC_WRITE = 0x40000000;
    const uint SHARE_ALL = 7;
    const uint CREATE_NEW = 1;
    const uint OPEN_EXISTING = 3;
    const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    static readonly IntPtr Invalid = new IntPtr(-1);
    [DllImport("ktmw32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateTransaction(IntPtr attributes, IntPtr uow, int options, int level, int flags, int timeout, string description);
    [DllImport("ktmw32.dll", SetLastError = true)]
    public static extern bool CommitTransaction(IntPtr transaction);
    [DllImport("ktmw32.dll", SetLastError = true)]
    public static extern bool RollbackTransaction(IntPtr transaction);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileTransactedW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr templateFile, IntPtr transaction, IntPtr miniVersion, IntPtr extended);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(IntPtr handle, byte[] data, uint length, out uint written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFilePointerEx(IntPtr handle, long distance, out long result, uint method);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetEndOfFile(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FlushFileBuffers(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
    public static void Replace(IntPtr transaction, string path, byte[] data, bool create) {
        uint disposition = create ? CREATE_NEW : OPEN_EXISTING;
        IntPtr handle = CreateFileTransactedW(path, GENERIC_WRITE, SHARE_ALL, IntPtr.Zero, disposition, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero, transaction, IntPtr.Zero, IntPtr.Zero);
        if (handle == Invalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            uint written;
            if (!WriteFile(handle, data, (uint)data.Length, out written, IntPtr.Zero) || written != data.Length) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            long moved;
            if (!SetFilePointerEx(handle, data.Length, out moved, 0) || !SetEndOfFile(handle) || !FlushFileBuffers(handle)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        } finally { CloseHandle(handle); }
    }
}
'@
}

$repair = $args -contains '-Repair'
$source = $(if ($repair) { $cache } else { $stage })
$versionPath = Join-Path $source 'winrtcs.version'
$sigPath = Join-Path $source 'winrtcs.version.sig'
if (-not (Test-Path -LiteralPath $versionPath)) { Fail 4 'MISSING_COMPONENT' }
$pins = Read-Pins $versionPath
$build = 0
[void][int]::TryParse($pins['BUILD_TS'], [ref]$build)
if ($build -lt $Floor) { Fail 3 'FLOOR' }
$payload = @{}
foreach ($name in $names) {
    $path = Join-Path $source $name
    if (-not (Test-Path -LiteralPath $path)) { Fail 4 'MISSING_COMPONENT' }
    $markers = @{
        'winrtcs_agent.cmd' = 'WINRTCS_AGENT'
        'winrtcs_guard.cmd' = 'WINRTCS_GUARD'
        'winrtcs_sentinel.cmd' = 'WINRTCS_SENTINEL'
        'winrtcs_run.cmd' = 'WINRTCS_RUN'
        'winrtcs_gen_commit.ps1' = 'WINRTCS_GEN_COMMIT'
        'winrtcs_device_client.ps1' = 'WINRTCS_DEVICE_CLIENT'
        'winrtcs_continuity.ps1' = 'WINRTCS_CONTINUITY'
        'winrtcs_watchdog.cmd' = 'WINRTCS_WATCHDOG'
        'winrtcs_wdgate.cmd' = 'WINRTCS_WDGATE'
        'winrtcs_keeper.ps1' = 'WINRTCS_KEEPER'
    }
    $markerName = $markers[$name]
    if ($name -eq 'winrtcs_device.cfg') {
        $text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($path)).Trim()
        if ($text -notmatch '\ADEVICE_BASE=https://[A-Za-z0-9.-]+/?\z') { Fail 4 'BAD_CONFIG' }
    } elseif ($markerName) {
        $marker = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($path))
        if ($marker.IndexOf($markerName) -lt 0) { Fail 4 'BAD_MARKER' }
    }
    $hash = Get-Sha256 $path
    $expected = $pins[$pinKeys[$name]]
    if (-not $expected -or $hash -ne $expected.ToLowerInvariant()) { Fail 3 'HASH_MISMATCH' }
    $payload[$name] = [IO.File]::ReadAllBytes($path)
}
if (-not (Test-Manifest $versionPath $sigPath)) { Fail 2 'BAD_SIG' }
$versionBytes = [IO.File]::ReadAllBytes($versionPath)
$sigBytes = [IO.File]::ReadAllBytes($sigPath)
if (-not $repair) {
    $liveVersion = Join-Path $zd 'winrtcs.version'
    $liveAgent = Join-Path $zd 'winrtcs_agent.cmd'
    $liveSig = Join-Path $zd 'winrtcs.version.sig'
    if ((Test-Path -LiteralPath $liveVersion) -and (Test-Path -LiteralPath $liveAgent) -and (Test-Path -LiteralPath $liveSig)) {
        $livePins = Read-Pins $liveVersion
        $livePin = $livePins['AGENT_SHA256']
        if ($livePin -and ((Get-Sha256 $liveAgent) -eq $livePin.ToLowerInvariant()) -and (Test-Manifest $liveVersion $liveSig)) {
            $liveBuild = 0
            [void][int]::TryParse($livePins['BUILD_TS'], [ref]$liveBuild)
            if ($build -lt $liveBuild) { Fail 3 'DOWNGRADE' }
        }
    }
    $currentVersion = Join-Path $cache 'winrtcs.version'
    $currentSig = Join-Path $cache 'winrtcs.version.sig'
    $currentAgent = Join-Path $cache 'winrtcs_agent.cmd'
    if (-not (Test-Path -LiteralPath $currentVersion) -or -not (Test-Path -LiteralPath $currentAgent)) { Fail 4 'NO_CURRENT' }
    $currentPins = Read-Pins $currentVersion
    $currentBuild = 0
    [void][int]::TryParse($currentPins['BUILD_TS'], [ref]$currentBuild)
    $agentHash = Get-Sha256 $currentAgent
    $pinnedAgent = $currentPins['AGENT_SHA256']
    $cacheCoherent = [bool]($pinnedAgent -and ($agentHash -eq $pinnedAgent.ToLowerInvariant()))
    if ($cacheCoherent) {
        $currentSigned = Test-Manifest $currentVersion $currentSig
        if ($currentSigned -and $build -lt $currentBuild) { Fail 3 'DOWNGRADE' }
        if (-not $currentSigned -and $build -le $currentBuild) { Fail 3 'FLOOR_UNSIGNED_CURRENT' }
        $same = $build -eq $currentBuild
        foreach ($name in $names) {
            $key = $pinKeys[$name]
            if ($currentPins.ContainsKey($key) -and $pins[$key].ToLowerInvariant() -ne $currentPins[$key].ToLowerInvariant()) { $same = $false }
        }
        if (-not $currentPins.ContainsKey('CLIENT_SHA256')) { $same = $false }
        foreach ($extra in @('PULSV_MSI_SHA256', 'PULSV_MSI_BYTES')) {
            if ([string]$currentPins[$extra] -ne [string]$pins[$extra]) { $same = $false }
        }
        if ($build -eq $currentBuild -and -not $same) { Fail 3 'SAME_TS_DIFFERENT_HASH' }
        if ($build -eq $currentBuild -and $same) {
            $liveComplete = $true
            foreach ($name in $names) {
                $live = Join-Path $zd $name
                if (-not (Test-Path -LiteralPath $live)) { $liveComplete = $false; break }
                $liveHash = Get-Sha256 $live
                $expect = $pins[$pinKeys[$name]]
                if (-not $expect -or $liveHash -ne $expect.ToLowerInvariant()) { $liveComplete = $false; break }
            }
            $liveVersion = Join-Path $zd 'winrtcs.version'
            $liveSig = Join-Path $zd 'winrtcs.version.sig'
            if ($liveComplete -and (Test-Path -LiteralPath $liveVersion) -and (Test-Path -LiteralPath $liveSig)) {
                Write-Result 'IDEMPOTENT'
                exit 0
            }
        }
        if ($build -lt $currentBuild) { Fail 3 'DOWNGRADE' }
    } else {
        $liveVersion = Join-Path $zd 'winrtcs.version'
        $liveAgent = Join-Path $zd 'winrtcs_agent.cmd'
        $liveSig = Join-Path $zd 'winrtcs.version.sig'
        if ((Test-Path -LiteralPath $liveVersion) -and (Test-Path -LiteralPath $liveAgent)) {
            $livePins = Read-Pins $liveVersion
            $livePin = $livePins['AGENT_SHA256']
            $liveHash = Get-Sha256 $liveAgent
            if ($livePin -and ($liveHash -eq $livePin.ToLowerInvariant())) {
                $liveBuild = 0
                [void][int]::TryParse($livePins['BUILD_TS'], [ref]$liveBuild)
                $liveSigned = Test-Manifest $liveVersion $liveSig
                if ($liveSigned -and $build -lt $liveBuild) { Fail 3 'DOWNGRADE' }
                if (-not $liveSigned -and $build -le $liveBuild) { Fail 3 'FLOOR_UNSIGNED_CURRENT' }
            }
        }
    }
}

$targets = @()
foreach ($root in @($zd, $cache)) {
    foreach ($name in ($names + @('winrtcs.version','winrtcs.version.sig'))) {
        $dest = Join-Path $root $name
        $targets += $dest
    }
    foreach ($mirror in @('ver.vps','ver.gh')) {
        $dest = Join-Path $root $mirror
        if (Test-Path -LiteralPath $dest) { $targets += $dest }
    }
}
$script:Txn = [GenTxn]::CreateTransaction([IntPtr]::Zero, [IntPtr]::Zero, 0, 0, 0, 0, 'gen-commit')
if ($script:Txn -eq [IntPtr]::Zero) { Fail 5 'TXF_UNAVAILABLE' }
$replaceFailed = $false
try {
    foreach ($dest in $targets) {
        $leaf = [IO.Path]::GetFileName($dest)
        $bytes = $versionBytes
        if ($leaf -eq 'winrtcs.version.sig') { $bytes = $sigBytes }
        elseif ($payload.ContainsKey($leaf)) { $bytes = $payload[$leaf] }
        [GenTxn]::Replace($script:Txn, $dest, $bytes, -not (Test-Path -LiteralPath $dest))
    }
    if (-not [GenTxn]::CommitTransaction($script:Txn)) { throw 'TXF_COMMIT' }
    $script:Committed = $true
} catch {
    $replaceFailed = $true
} finally {
    if (-not $script:Committed -and $script:Txn -ne [IntPtr]::Zero) { [GenTxn]::RollbackTransaction($script:Txn) | Out-Null }
    if ($script:Txn -ne [IntPtr]::Zero) { [GenTxn]::CloseHandle($script:Txn) | Out-Null }
}
if ($replaceFailed -or -not $script:Committed) {
    Write-Result 'OLD_COMPLETE'
    exit 5
}
Write-Result 'NEW_COMPLETE'
exit 0
