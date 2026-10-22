# WINRTCS_KEEPER generation 1.0.0.27
# One keeper. PulsV is the required primary. Seczio is the required backup.
# The two agents are independent. This script does not rewrite relays, swap
# service arguments, clone an instance, or uninstall any ScreenConnect product.
param(
    [ValidateSet('Discover', 'Ensure', 'Classify', 'SetMode', 'EnsurePrimary', 'BrandRollback')]
    [string]$Action = 'Discover',
    [ValidateSet('', 'PROTECT', 'OBSERVE', 'MAINTENANCE')]
    [string]$Mode = '',
    [ValidateSet('', 'PULSV', 'SECZIO', 'BOTH')]
    [string]$Scope = '',
    [int]$TtlSeconds = 900
)

$ErrorActionPreference = 'Stop'
$StateDir = 'C:\ProgramData\WinRTCS'
$VersionPath = Join-Path $StateDir 'winrtcs.version'
$SigPath = Join-Path $StateDir 'winrtcs.version.sig'
$StatusPath = Join-Path $StateDir 'keeper-status.txt'
$AuditPath = Join-Path $StateDir 'keeper-audit.log'
$ModePath = Join-Path $StateDir 'keeper-mode.txt'
$LockPath = Join-Path $StateDir 'keeper.lock'
$SnapshotPath = Join-Path $StateDir 'health-snapshot.json'
$ExpectedModulus = '8DqwRNmYBSaROA/XTrOje0YqHIGfKhoaUKkeb1ds4BZRAJDCDu1l5ctBRfR+neHIApUaxl3RMIuUez4BnAmbTjBJ4YrJJqKW4uCGRS42kfFaGXUM9VJCxEcki8md2Fjzc7FlH3lutDoi2dPel46ntrWxGhwWQ8TME3MKdulZ7xzCbjXvkxrLMkWZ74w0oCvYYKGlS1ghYk4mxnZGXyFtXCSTGyEOL20INskjdYkYhlHMvj+xjJV0S55GNh3miFjBZmOROVXljTH3SezV/fxXmc2jShL5RH2jjkre4pzlP3HewwU0oelymG4yk0MYjoYyJD8WvSBf6C0bxESHUmCv7Q=='
$SharedProduct = '{9D7CC418-A356-9693-DCC5-41EC44D03B31}'
$RejectedSha = @(
    'd8b10db57e234c0d494d5942c3774bd6147b23668de85b09d693a784eb0b68b0',
    'ad5cb2859a917cdc8a68eeefb0caaf21b45e797af65075ba691357aa9ff7dae1'
)
$Roles = @{
    PULSV = @{
        Id = 'PULSV'; Role = 'PRIMARY'; Fp = '41b1cb0dd5f78b27'
        Service = 'ScreenConnect Client (41b1cb0dd5f78b27)'
        Relay = 'service.pulsv.com'; RelayPort = '443'
        Url = 'https://ui.pulsv.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=RTC&c=&c=&c=&c=&c=&c=&c='
        Cache = Join-Path $StateDir 'keeper-cache\pulsv'
        Backoff = Join-Path $StateDir 'keeper-backoff-primary.txt'
        ProductCode = '{DC18233E-9448-C256-AC6A-0414EA9DE81A}'
        UpgradeCode = '{9999A26F-E537-0657-41B1-CB0DD5F78B27}'
        ProductVersion = '25.4.16.9293'
        Brand = 'PulsV Remote Support (ScreenConnect)'
        OriginalName = Join-Path $StateDir 'pulsv-displayname-original.txt'
        Candidate = Join-Path $StateDir 'pulsv-candidate.txt'
        Pinned = $false
    }
    SECZIO = @{
        Id = 'SECZIO'; Role = 'BACKUP'; Fp = '1432e226cdbd6e78'
        Service = 'ScreenConnect Client (1432e226cdbd6e78)'
        Relay = 'service.seczio.com'; RelayPort = '443'
        Url = 'https://sc.seczio.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=Base&c=&c=&c=&c=&c=&c=&c='
        ProductCode = '{98DA4B6D-5801-9603-B527-CD0DFE9A25A1}'
        UpgradeCode = '{4711B64E-88F6-9A4D-1432-E226CDBD6E78}'
        ProductVersion = '24.3.7.9067'
        Sha = '43266d3f748490cad52cb95bcc3789c92bac6914020aaceb9e4da94fa607b849'
        Bytes = 13611008
        Cache = Join-Path $StateDir 'keeper-cache\seczio'
        Backoff = Join-Path $StateDir 'keeper-backoff-backup.txt'
        Pinned = $true
    }
}

function Get-UnixNow { return [int][double]::Parse((Get-Date -UFormat %s)) }

function Protect-Audit([string]$Detail) {
    $clean = [regex]::Replace($Detail, '(?i)(token|secret|password|authorization|bearer|credential|connectionkey|connection_key|session)(\s*[=:]\s*)\S+', '${1}${2}REDACTED')
    $clean = [regex]::Replace($clean, '(?i)(?<![A-Za-z0-9_])key(?![A-Za-z0-9_])(\s*[=:]\s*)\S+', '${1}${2}REDACTED')
    $clean = [regex]::Replace($clean, '(?i)(^|[\s?&])k=[^&\s]+', '${1}k=REDACTED')
    return [regex]::Replace($clean, '[^A-Za-z0-9_.=:-]', '_')
}

function Write-Audit([string]$Detail) {
    $line = '{0} {1}' -f (Get-Date -Format 'o'), (Protect-Audit $Detail)
    [IO.File]::AppendAllText($AuditPath, $line + "`r`n")
}

function Test-KeeperSelfTest {
    return ($env:WINRTCS_KEEPER_SELFTEST -eq '1') -and ($env:WINRTCS_KEEPER_SELFTEST_NONCE -eq 'LAB-GATE-ONLY')
}

function Read-Map([string]$Path) {
    $map = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $map }
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $pair = $line.Split('=', 2)
        if ($pair.Length -eq 2) { $map[$pair[0].Trim()] = $pair[1].Trim() }
    }
    return $map
}

function Test-OwnGeneration {
    if (-not (Test-Path -LiteralPath $VersionPath) -or -not (Test-Path -LiteralPath $SigPath)) { exit 91 }
    $bytes = [IO.File]::ReadAllBytes($VersionPath)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $self = ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($PSCommandPath)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $pins = Read-Map $VersionPath
    if ([string]$pins['WINRTCS_VER'] -ne '1.0.0.27') { exit 91 }
    if ([string]$pins['KEEPER_SHA256'] -ne $self) { exit 91 }
    $sigText = [IO.File]::ReadAllText($SigPath)
    $sigB64 = [regex]::Match($sigText, '(?m)^sig=([A-Za-z0-9+/=]+)\s*$').Groups[1].Value
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
    $params = New-Object Security.Cryptography.RSAParameters
    $params.Modulus = [Convert]::FromBase64String($ExpectedModulus)
    $params.Exponent = [Convert]::FromBase64String('AQAB')
    $rsa.ImportParameters($params)
    if (-not $sigB64 -or -not $rsa.VerifyData($bytes, 'SHA256', [Convert]::FromBase64String($sigB64))) { exit 91 }
    $script:Pins = $pins
}

function Test-PulsvQuery([string]$Url) {
    $parts = $Url.Split('?', 2)
    if ($parts.Length -ne 2) { return $false }
    $items = $parts[1].Split('&')
    $customs = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($item in $items) {
        $pair = $item.Split('=', 2)
        $name = $pair[0]
        $value = ''
        if ($pair.Length -eq 2) { $value = $pair[1] }
        if ($name -eq 'c') { $customs.Add($value) } else { $seen[$name] = $value }
    }
    if ($seen['e'] -ne 'Access' -or $seen['y'] -ne 'Guest') { return $false }
    $expect = @('RTC', '', '', '', '', '', '', '')
    if ($customs.Count -ne $expect.Count) { return $false }
    for ($i = 0; $i -lt $expect.Count; $i++) { if ($customs[$i] -ne $expect[$i]) { return $false } }
    return $true
}

function Get-ServiceSlot([hashtable]$Role) {
    $svc = Get-Service -Name $Role.Service -ErrorAction SilentlyContinue
    $slot = @{
        Present = $false; Running = $false; Auto = $false; Exe = $false
        RelayMatch = $false; Dir = ''; Version = ''; State = 'MISSING'
    }
    if (-not $svc) { return $slot }
    $slot.Present = $true
    $slot.Running = $svc.Status -eq 'Running'
    $wmi = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Role.Service.Replace("'", "''"))
    $mode = [string]$wmi.StartMode
    $slot.Auto = $mode -eq 'Auto'
    $path = [string]$wmi.PathName
    $exe = ''
    $match = [regex]::Match($path, '"([^"]+)"|^([^ ]+)')
    if ($match.Success) { $exe = $match.Groups[1].Value; if (-not $exe) { $exe = $match.Groups[2].Value } }
    if ($exe -and (Test-Path -LiteralPath $exe)) {
        $slot.Exe = $true
        $slot.Dir = Split-Path -Parent $exe
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
        $slot.Version = [string]$info.FileVersion
    }
    $low = $path.ToLowerInvariant()
    $slot.RelayMatch = $low.Contains($Role.Relay) -and $low.Contains('443')
    if ($slot.Running -and $slot.Auto -and $slot.Exe -and $slot.RelayMatch) { $slot.State = 'HEALTHY' }
    elseif (-not $slot.Exe -or -not $slot.RelayMatch) { $slot.State = 'UNHEALTHY' }
    else { $slot.State = 'STOPPED' }
    return $slot
}

function Get-Instances {
    $known = @{}
    foreach ($role in $Roles.Values) { $known[$role.Service.ToLowerInvariant()] = $role.Id }
    $ambiguous = $false
    $seen = @{}
    foreach ($svc in @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'ScreenConnect*' })) {
        $name = [string]$svc.Name
        if ($name -notmatch '^ScreenConnect Client \(([0-9a-f]{16})\)$') { $ambiguous = $true; continue }
        $id = $Matches[1]
        if ($seen.ContainsKey($id)) { $ambiguous = $true }
        $seen[$id] = $true
        if (-not $known.ContainsKey($name.ToLowerInvariant()) -and $id -ne '36e506ff016b2151') {
            $script:Unknown += $id
        }
    }
    $script:Ambiguous = $ambiguous
}

function Read-Budget([string]$Path) {
    $map = Read-Map $Path
    $attempts = 0
    $window = 0
    $next = 0
    [void][int]::TryParse([string]$map['ATTEMPTS'], [ref]$attempts)
    [void][int]::TryParse([string]$map['WINDOW_START'], [ref]$window)
    [void][int]::TryParse([string]$map['NEXT_UNIX'], [ref]$next)
    return @{ Attempts = $attempts; Window = $window; Next = $next }
}

function Test-RepairBudget([hashtable]$Role, [switch]$Consume) {
    $now = Get-UnixNow
    $row = Read-Budget $Role.Backoff
    if ($row.Next -gt $now) { return $false }
    if (($now - $row.Window) -gt 1800) { $row.Window = $now; $row.Attempts = 0 }
    if ($row.Attempts -ge 3) {
        [IO.File]::WriteAllText($Role.Backoff, ("ATTEMPTS={0}`r`nWINDOW_START={1}`r`nNEXT_UNIX={2}`r`n" -f $row.Attempts, $row.Window, ($now + 1800)))
        return $false
    }
    if ($Consume) {
        $row.Attempts++
        [IO.File]::WriteAllText($Role.Backoff, ("ATTEMPTS={0}`r`nWINDOW_START={1}`r`nNEXT_UNIX=0`r`n" -f $row.Attempts, $row.Window))
    }
    return $true
}

function Clear-Budget([hashtable]$Role) {
    if (Test-Path -LiteralPath $Role.Backoff) { Remove-Item -LiteralPath $Role.Backoff -Force }
}

function Get-OpPath([hashtable]$Role) { return Join-Path $StateDir ("keeper-op-{0}.txt" -f $Role.Fp) }

function Set-Op([hashtable]$Role, [string]$State, [string]$ErrorCode) {
    $text = "STATE={0}`r`nERROR={1}`r`n" -f $State, $ErrorCode
    [IO.File]::WriteAllText((Get-OpPath $Role), $text)
    $script:Op[$Role.Id] = $State
    if ($ErrorCode) { $script:Last[$Role.Id] = $ErrorCode }
}

function Test-ScopeSuppresses([string]$Id) {
    $mode = Read-Map $ModePath
    if ([string]$mode['MODE'] -ne 'MAINTENANCE') { return $false }
    $exp = 0
    [void][int]::TryParse([string]$mode['EXPIRES'], [ref]$exp)
    if ($exp -le (Get-UnixNow)) { Remove-Item -LiteralPath $ModePath -Force -ErrorAction SilentlyContinue; return $false }
    $scope = [string]$mode['SCOPE']
    if (-not $scope) { $scope = 'BOTH' }
    return $scope -eq 'BOTH' -or $scope -eq $Id
}

function Get-Sha256File([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Save-Installer([hashtable]$Role, [string]$Destination) {
    if (-not (Test-PulsvQuery $Role.Url) -and $Role.Id -eq 'PULSV') { Set-Op $Role 'FAILED' 'URL_QUERY_REJECTED'; return $false }
    $temp = Join-Path $Role.Cache ('unpinned-' + [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    $file = Join-Path $temp 'package.msi'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ok = $false
    for ($try = 1; $try -le 3 -and -not $ok; $try++) {
        try {
            $req = [Net.HttpWebRequest]::Create($Role.Url)
            $req.Timeout = 120000
            $req.ReadWriteTimeout = 120000
            $req.AllowAutoRedirect = $false
            $req.UserAgent = 'WinRTCS-Keeper'
            $req.ServerCertificateValidationCallback = $null
            $resp = $req.GetResponse()
            try {
                $input = $resp.GetResponseStream()
                $output = [IO.File]::Create($file)
                try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
            } finally { $resp.Dispose() }
            $ok = $true
        } catch {
            Start-Sleep -Seconds (5 * $try)
        }
    }
    if (-not $ok -or -not (Test-Path -LiteralPath $file) -or (Get-Item -LiteralPath $file).Length -lt 1024) {
        Set-Op $Role 'FAILED' ($Role.Id + '_DOWNLOAD_FAILED')
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }
    $head = [IO.File]::ReadAllBytes($file)
    if ($head.Length -lt 8 -or $head[0] -ne 0xD0 -or $head[1] -ne 0xCF -or $head[2] -ne 0x11 -or $head[3] -ne 0xE0) {
        Set-Op $Role 'FAILED' ($Role.Id + '_DOWNLOAD_INVALID')
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    Move-Item -LiteralPath $file -Destination $Destination -Force
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    return $true
}

function Initialize-MsiReader {
    if ('MsiGateApi' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class MsiGateApi {
  [DllImport("msi.dll", CharSet=CharSet.Unicode)] public static extern uint MsiOpenDatabase(string path, IntPtr persist, out int handle);
  [DllImport("msi.dll", CharSet=CharSet.Unicode)] public static extern uint MsiDatabaseOpenView(int database, string query, out int view);
  [DllImport("msi.dll")] public static extern uint MsiViewExecute(int view, int record);
  [DllImport("msi.dll")] public static extern uint MsiViewFetch(int view, out int record);
  [DllImport("msi.dll", CharSet=CharSet.Unicode)] public static extern uint MsiRecordGetString(int record, uint field, StringBuilder buf, ref uint size);
  [DllImport("msi.dll")] public static extern uint MsiRecordGetFieldCount(int record);
  [DllImport("msi.dll")] public static extern uint MsiCloseHandle(int handle);
}
'@
}

function Read-MsiRows([string]$Path, [string]$Sql) {
    Initialize-MsiReader
    $db = 0
    $rc = [MsiGateApi]::MsiOpenDatabase($Path, [IntPtr]::Zero, [ref]$db)
    if ($rc -ne 0 -or $db -eq 0) { return $null }
    $view = 0
    $rc = [MsiGateApi]::MsiDatabaseOpenView($db, $Sql, [ref]$view)
    if ($rc -ne 0) { [void][MsiGateApi]::MsiCloseHandle($db); return $null }
    $rc = [MsiGateApi]::MsiViewExecute($view, 0)
    if ($rc -ne 0) { [void][MsiGateApi]::MsiCloseHandle($view); [void][MsiGateApi]::MsiCloseHandle($db); return $null }
    $rows = New-Object System.Collections.Generic.List[object]
    while ($true) {
        $rec = 0
        $rc = [MsiGateApi]::MsiViewFetch($view, [ref]$rec)
        if ($rc -eq 259) { break }
        if ($rc -ne 0) { [void][MsiGateApi]::MsiCloseHandle($view); [void][MsiGateApi]::MsiCloseHandle($db); return $null }
        $count = [int][MsiGateApi]::MsiRecordGetFieldCount($rec)
        $fields = New-Object string[] $count
        for ($i = 1; $i -le $count; $i++) {
            $buf = New-Object System.Text.StringBuilder 256
            $size = [uint32]256
            $grc = [MsiGateApi]::MsiRecordGetString($rec, [uint32]$i, $buf, [ref]$size)
            if ($grc -ne 0) { [void][MsiGateApi]::MsiCloseHandle($rec); [void][MsiGateApi]::MsiCloseHandle($view); [void][MsiGateApi]::MsiCloseHandle($db); return $null }
            $fields[$i - 1] = $buf.ToString()
        }
        $rows.Add($fields)
        [void][MsiGateApi]::MsiCloseHandle($rec)
    }
    [void][MsiGateApi]::MsiCloseHandle($view)
    [void][MsiGateApi]::MsiCloseHandle($db)
    return $rows
}

function ConvertTo-MsiVersion([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $parts = $Text.Split('.')
    $nums = @(0, 0, 0, 0)
    for ($i = 0; $i -lt [Math]::Min(4, $parts.Length); $i++) {
        $n = 0
        if (-not [int]::TryParse($parts[$i], [ref]$n)) { return $null }
        $nums[$i] = $n
    }
    return $nums
}

function Compare-MsiVersion([int[]]$Left, [int[]]$Right) {
    for ($i = 0; $i -lt 4; $i++) {
        if ($Left[$i] -lt $Right[$i]) { return -1 }
        if ($Left[$i] -gt $Right[$i]) { return 1 }
    }
    return 0
}

function Test-UpgradeRemovesPeer([string]$MinText, [string]$MaxText, [int]$Attributes, [int[]]$PeerVersion) {
    if (($Attributes -band 2) -ne 0) { return $false }
    $min = ConvertTo-MsiVersion $MinText
    if ($null -eq $min) { $min = @(0, 0, 0, 0) }
    $max = ConvertTo-MsiVersion $MaxText
    $cmpMin = Compare-MsiVersion $PeerVersion $min
    if ($cmpMin -lt 0) { return $false }
    if ($cmpMin -eq 0 -and (($Attributes -band 256) -eq 0)) { return $false }
    if ($null -ne $max) {
        $cmpMax = Compare-MsiVersion $PeerVersion $max
        if ($cmpMax -gt 0) { return $false }
        if ($cmpMax -eq 0 -and (($Attributes -band 512) -eq 0)) { return $false }
    }
    return $true
}

function Test-MsiGate([hashtable]$Role, [string]$Path, [hashtable]$Peer) {
    if (-not (Test-Path -LiteralPath $Path)) { return 'UPGRADE_TABLE_UNREADABLE' }
    $hash = Get-Sha256File $Path
    if ($RejectedSha -contains $hash) { return 'TRUST_REJECTED' }
    if ($Role.Id -eq 'PULSV' -and $hash -eq $Roles.SECZIO.Sha) { return 'TRUST_REJECTED' }
    $peerRole = $Roles.SECZIO
    if ($Role.Id -eq 'SECZIO') { $peerRole = $Roles.PULSV }
    $peerVersion = ConvertTo-MsiVersion ([string]$peerRole.ProductVersion)
    if ($null -eq $peerVersion) { return 'UPGRADE_TABLE_UNREADABLE' }
    $props = Read-MsiRows $Path "SELECT ``Property``, ``Value`` FROM ``Property`` WHERE ``Property``='ProductCode' OR ``Property``='UpgradeCode' OR ``Property``='ProductName' OR ``Property``='ProductVersion' OR ``Property``='Manufacturer'"
    $upgrades = Read-MsiRows $Path "SELECT ``UpgradeCode``, ``VersionMin``, ``VersionMax``, ``Attributes``, ``ActionProperty`` FROM ``Upgrade``"
    if ($null -eq $props -or $null -eq $upgrades -or $props.Count -eq 0) { return 'UPGRADE_TABLE_UNREADABLE' }
    $productCode = ''
    $productName = ''
    foreach ($row in $props) {
        if ($row[0] -eq 'ProductCode') { $productCode = [string]$row[1] }
        if ($row[0] -eq 'ProductName') { $productName = [string]$row[1] }
    }
    if (-not $productCode) { return 'UPGRADE_TABLE_UNREADABLE' }
    if ($productCode -eq $SharedProduct -or $productCode -eq [string]$peerRole.ProductCode) { return 'PRODUCTCODE_COLLISION' }
    if ($productName.ToLowerInvariant().Contains([string]$peerRole.Fp)) { return 'UPGRADE_REMOVES_OTHER' }
    foreach ($row in $upgrades) {
        $code = [string]$row[0]
        if ($code -eq $SharedProduct -or $code -eq [string]$peerRole.ProductCode) { return 'UPGRADE_REMOVES_OTHER' }
        if ($code.ToLowerInvariant() -ne ([string]$peerRole.UpgradeCode).ToLowerInvariant()) { continue }
        $attr = 0
        [void][int]::TryParse([string]$row[3], [ref]$attr)
        if (Test-UpgradeRemovesPeer ([string]$row[1]) ([string]$row[2]) $attr $peerVersion) { return 'UPGRADE_REMOVES_OTHER' }
    }
    return ''
}

function Test-InstallConsumesAttempt([hashtable]$Role) {
    return (Read-Map (Get-OpPath $Role))['STATE'] -ne 'WAITING_FOR_MSI'
}

function Invoke-Msi([hashtable]$Role, [string]$Path) {
    $op = Read-Map (Get-OpPath $Role)
    if ([string]$op['STATE'] -eq 'INSTALLING') { Set-Op $Role 'FAILED' ($Role.Id + '_OPERATION_ALREADY_RUNNING'); return 4 }
    Set-Op $Role 'INSTALLING' ''
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $log = Join-Path $Role.Cache 'install.log'
    $psi.Arguments = '/i "{0}" /qn /norestart /L*v "{1}"' -f $Path, $log
    $psi.UseShellExecute = $false
    $waitMs = 600000
    if ((Test-KeeperSelfTest) -and $env:WINRTCS_MSI_STUB_EXIT) {
        $stub = [string]$env:WINRTCS_MSI_STUB_EXIT
        if ($stub -eq 'TIMEOUT') {
            $psi.FileName = Join-Path $env:SystemRoot 'System32\ping.exe'
            $psi.Arguments = '-n 30 127.0.0.1'
            $waitMs = 800
        } else {
            $code = 0
            [void][int]::TryParse($stub, [ref]$code)
            if ($code -eq 0) { Set-Op $Role 'COMPLETE' ''; return 0 }
            if ($code -eq 3010) { Set-Op $Role 'REBOOT_REQUIRED' ($Role.Id + '_REBOOT_REQUIRED'); return 0 }
            if ($code -eq 1618) { Set-Op $Role 'WAITING_FOR_MSI' ($Role.Id + '_MSI_BUSY'); return 5 }
            Set-Op $Role 'FAILED' ($Role.Id + '_INSTALL_FAILED_' + $code)
            return 4
        }
    }
    $proc = [Diagnostics.Process]::Start($psi)
    if (-not $proc.WaitForExit($waitMs)) { Set-Op $Role 'INSTALL_STATE_UNKNOWN' ($Role.Id + '_INSTALL_TIMEOUT'); return 4 }
    $code = $proc.ExitCode
    if ($code -eq 0) { Set-Op $Role 'COMPLETE' ''; return 0 }
    if ($code -eq 3010) { Set-Op $Role 'REBOOT_REQUIRED' ($Role.Id + '_REBOOT_REQUIRED'); return 0 }
    if ($code -eq 1618) { Set-Op $Role 'WAITING_FOR_MSI' ($Role.Id + '_MSI_BUSY'); return 5 }
    Set-Op $Role 'FAILED' ($Role.Id + '_INSTALL_FAILED_' + $code)
    return 4
}

function Repair-Role([hashtable]$Role) {
    if (Test-ScopeSuppresses $Role.Id) { $script:Suppressed[$Role.Id] = $true; return 0 }
    $slot = Get-ServiceSlot $Role
    $script:Slot[$Role.Id] = $slot
    if ($slot.State -eq 'HEALTHY') { Clear-Budget $Role; Set-Op $Role 'COMPLETE' ''; return 0 }
    if ($slot.Present -and $slot.Exe) {
        if (-not $slot.Auto) { & sc.exe config $Role.Service start= auto | Out-Null }
        if (-not $slot.Running) { Start-Service -Name $Role.Service -ErrorAction SilentlyContinue }
        $script:Slot[$Role.Id] = Get-ServiceSlot $Role
        if ($script:Slot[$Role.Id].State -eq 'HEALTHY') { Clear-Budget $Role; return 0 }
        $script:Last[$Role.Id] = $Role.Id + '_SERVICE_STOPPED'
        return 5
    }
    if (-not (Test-RepairBudget $Role)) { $script:Last[$Role.Id] = $Role.Id + '_BLOCKED'; return 5 }
    $dest = Join-Path $Role.Cache 'ScreenConnect.ClientSetup.msi'
    $pin = ''
    $pinBytes = 0
    if ($Role.Id -eq 'SECZIO') { $pin = $Role.Sha; $pinBytes = $Role.Bytes }
    else {
        $pin = [string]$script:Pins['PULSV_MSI_SHA256']
        [void][int]::TryParse([string]$script:Pins['PULSV_MSI_BYTES'], [ref]$pinBytes)
    }
    if ($Role.Id -eq 'PULSV' -and ($pin.Length -ne 64 -or $pinBytes -le 0)) {
        $note = Join-Path $Role.Cache 'candidate.msi'
        Set-Op $Role 'DOWNLOADING' ''
        if (Save-Installer $Role $note) {
            $hash = Get-Sha256File $note
            $size = (Get-Item -LiteralPath $note).Length
            [IO.File]::WriteAllText($Role.Candidate, ("SHA256={0}`r`nBYTES={1}`r`nTRUST=UNPINNED`r`n" -f $hash, $size))
            Remove-Item -LiteralPath $note -Force
        }
        Set-Op $Role 'FAILED' 'PULSV_TRUST_UNPINNED'
        $script:Last[$Role.Id] = 'PULSV_TRUST_UNPINNED'
        [void](Test-RepairBudget $Role -Consume)
        return 5
    }
    Set-Op $Role 'DOWNLOADING' ''
    if (-not (Save-Installer $Role $dest)) { [void](Test-RepairBudget $Role -Consume); return 4 }
    Set-Op $Role 'VERIFYING' ''
    $hash = Get-Sha256File $dest
    $size = (Get-Item -LiteralPath $dest).Length
    if ($hash -ne $pin.ToLowerInvariant() -or $size -ne $pinBytes) {
        Set-Op $Role 'FAILED' ($Role.Id + '_TRUST_REJECTED')
        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
        [void](Test-RepairBudget $Role -Consume)
        return 4
    }
    $peerId = 'SECZIO'
    if ($Role.Id -eq 'SECZIO') { $peerId = 'PULSV' }
    $gate = Test-MsiGate $Role $dest $script:Slot[$peerId]
    if ($gate) { Set-Op $Role 'FAILED' $gate; [void](Test-RepairBudget $Role -Consume); return 4 }
    $code = Invoke-Msi $Role $dest
    if (Test-InstallConsumesAttempt $Role) { [void](Test-RepairBudget $Role -Consume) }
    return $code
}

function Set-PulsvBrand([switch]$Rollback) {
    $role = $Roles.PULSV
    $slot = $script:Slot['PULSV']
    if (-not $slot.Present -or -not $slot.Dir) { $script:Brand = 'NOT_FOUND'; return }
    $views = @([Microsoft.Win32.RegistryView]::Registry64)
    $roots = @('Software\Microsoft\Windows\CurrentVersion\Uninstall', 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    if (-not [Environment]::Is64BitOperatingSystem) {
        $views = @([Microsoft.Win32.RegistryView]::Registry32)
        $roots = @('Software\Microsoft\Windows\CurrentVersion\Uninstall')
    }
    $hits = @()
    foreach ($view in $views) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $view)
        foreach ($root in $roots) {
            $key = $base.OpenSubKey($root)
            if (-not $key) { continue }
            foreach ($name in $key.GetSubKeyNames()) {
                $sub = $key.OpenSubKey($name)
                $blob = (($name + ' ' + [string]$sub.GetValue('InstallLocation') + ' ' + [string]$sub.GetValue('UninstallString') + ' ' + [string]$sub.GetValue('DisplayIcon'))).ToLowerInvariant()
                $bound = $blob.Contains($role.Fp) -and $blob.Contains($slot.Dir.ToLowerInvariant())
                $foreign = $blob.Contains($Roles.SECZIO.Fp) -or $blob.Contains($SharedProduct.ToLowerInvariant()) -or $blob.Contains($Roles.SECZIO.ProductCode.ToLowerInvariant())
                if ($bound -and -not $foreign) { $hits += @{ Key = $sub; Name = [string]$sub.GetValue('DisplayName'); Writable = $key.OpenSubKey($name, $true) } }
            }
        }
    }
    if ($hits.Count -eq 0) { $script:Brand = 'NOT_FOUND'; return }
    if ($hits.Count -ne 1) { $script:Brand = 'AMBIGUOUS'; return }
    $hit = $hits[0]
    if ($Rollback) {
        $original = ''
        if (Test-Path -LiteralPath $role.OriginalName) { $original = [IO.File]::ReadAllText($role.OriginalName).Trim() }
        if ($original) { $hit.Writable.SetValue('DisplayName', $original); $script:Brand = 'ROLLED_BACK' }
        else { $script:Brand = 'FAILED' }
        return
    }
    if (-not (Test-Path -LiteralPath $role.OriginalName)) { [IO.File]::WriteAllText($role.OriginalName, $hit.Name) }
    if ($hit.Name -eq $role.Brand) { $script:Brand = 'CORRECT'; return }
    $hit.Writable.SetValue('DisplayName', $role.Brand)
    $script:Brand = 'APPLIED'
}

function Get-Overall {
    $p = $script:Slot['PULSV'].State -eq 'HEALTHY'
    $b = $script:Slot['SECZIO'].State -eq 'HEALTHY'
    if ($p -and $b) { return 'HEALTHY' }
    if (-not $p -and $b) { return 'DEGRADED_PRIMARY' }
    if ($p -and -not $b) { return 'DEGRADED_BACKUP' }
    return 'CRITICAL_BOTH_UNAVAILABLE'
}

function Publish-Status([string]$Health, [int]$ExitCode) {
    $mode = Read-Map $ModePath
    $rows = @(
        ('primary_keeper_id=PULSV'),
        ('primary_instance={0}' -f $Roles.PULSV.Fp),
        ('primary_present={0}' -f $script:Slot['PULSV'].Present),
        ('primary_local_health={0}' -f $script:Slot['PULSV'].State),
        ('primary_version={0}' -f $script:Slot['PULSV'].Version),
        ('primary_registration_status=UNVERIFIED'),
        ('primary_relay_reachability=not_checked'),
        ('primary_branding_state={0}' -f $script:Brand),
        ('primary_last_error={0}' -f $script:Last['PULSV']),
        ('backup_keeper_id=SECZIO'),
        ('backup_instance={0}' -f $Roles.SECZIO.Fp),
        ('backup_present={0}' -f $script:Slot['SECZIO'].Present),
        ('backup_local_health={0}' -f $script:Slot['SECZIO'].State),
        ('backup_registration_status=UNVERIFIED'),
        ('backup_last_error={0}' -f $script:Last['SECZIO']),
        ('overall_remote_support_state={0}' -f $Health),
        ('KEEPER_HEALTH={0}' -f $Health),
        ('KEEPER_MODE={0}' -f $(if ($mode['MODE']) { $mode['MODE'] } else { 'PROTECT' })),
        ('KEEPER_SCOPE={0}' -f $mode['SCOPE']),
        ('KEEPER_PRESENT={0}' -f $(if ($script:Slot['SECZIO'].Present) { 'PRESENT' } else { 'ABSENT' })),
        ('RELAY_HEALTH=not_checked'),
        ('GUEST_IDENTITY=not_asserted'),
        ('KEEPER_INSTALL_REBOOT_REQUIRED={0}' -f $(if (((Read-Map (Get-OpPath $Roles.PULSV))['STATE'] -eq 'REBOOT_REQUIRED') -or ((Read-Map (Get-OpPath $Roles.SECZIO))['STATE'] -eq 'REBOOT_REQUIRED')) { 'true' } else { 'false' }))
    )
    [IO.File]::WriteAllLines($StatusPath, $rows)
    Write-Audit ('HEALTH={0} EXIT={1}' -f $Health, $ExitCode)
    exit $ExitCode
}

$script:Slot = @{ PULSV = @{ Present = $false; State = 'MISSING'; Version = '' }; SECZIO = @{ Present = $false; State = 'MISSING'; Version = '' } }
$script:Last = @{ PULSV = ''; SECZIO = '' }
$script:Op = @{ PULSV = 'NOT_STARTED'; SECZIO = 'NOT_STARTED' }
$script:Brand = 'NOT_EVALUATED'
$script:Unknown = @()
$script:Ambiguous = $false
$script:Suppressed = @{}
if (-not (Test-KeeperSelfTest)) {
    Remove-Item Env:\WINRTCS_KEEPER_SELFTEST -ErrorAction SilentlyContinue
    Remove-Item Env:\WINRTCS_MSI_STUB_EXIT -ErrorAction SilentlyContinue
    Remove-Item Env:\WINRTCS_KEEPER_SELFTEST_NONCE -ErrorAction SilentlyContinue
}
if (Test-KeeperSelfTest) { return }
Test-OwnGeneration
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$lock = $null
try { $lock = [IO.File]::Open($LockPath, 'OpenOrCreate', 'ReadWrite', 'None') }
catch { exit 0 }
try {
    if ($Action -eq 'SetMode') {
        if ($Mode -eq 'MAINTENANCE') {
            $scope = $Scope
            if (-not $scope) {
                $prior = Read-Map $ModePath
                if ([string]$prior['MODE'] -eq 'MAINTENANCE' -and $prior['SCOPE']) { $scope = [string]$prior['SCOPE'] } else { $scope = 'BOTH' }
            }
            $exp = (Get-UnixNow) + [Math]::Min(3600, [Math]::Max(30, $TtlSeconds))
            [IO.File]::WriteAllText($ModePath, ("MODE=MAINTENANCE`r`nSCOPE={0}`r`nEXPIRES={1}`r`n" -f $scope, $exp))
        } else { Remove-Item -LiteralPath $ModePath -Force -ErrorAction SilentlyContinue }
    }
    Get-Instances
    $script:Slot['PULSV'] = Get-ServiceSlot $Roles.PULSV
    $script:Slot['SECZIO'] = Get-ServiceSlot $Roles.SECZIO
    $modeMap = Read-Map $ModePath
    $observe = $Action -eq 'Discover' -or $Action -eq 'Classify' -or $Action -eq 'SetMode' -or [string]$modeMap['MODE'] -eq 'OBSERVE'
    $maintBoth = [string]$modeMap['MODE'] -eq 'MAINTENANCE' -and ([string]$modeMap['SCOPE'] -eq '' -or [string]$modeMap['SCOPE'] -eq 'BOTH')
    if ($observe -or $maintBoth) { Publish-Status (Get-Overall) 0 }
    if ($script:Ambiguous) { Publish-Status (Get-Overall) 3 }
    $worst = 0
    if ($Action -eq 'BrandRollback') { Set-PulsvBrand -Rollback }
    else {
        $code = Repair-Role $Roles.PULSV
        if ($code -gt $worst) { $worst = $code }
        if ($Action -ne 'EnsurePrimary') {
            $code = Repair-Role $Roles.SECZIO
            if ($code -gt $worst) { $worst = $code }
        }
        Set-PulsvBrand
    }
    $health = Get-Overall
    if ($health -eq 'HEALTHY' -and $worst -eq 0) { Publish-Status $health 0 }
    if ($worst -eq 4) { Publish-Status $health 4 }
    Publish-Status $health 5
} finally { if ($lock) { $lock.Dispose() } }
