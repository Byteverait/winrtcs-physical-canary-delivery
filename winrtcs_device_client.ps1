# WINRTCS_DEVICE_CLIENT
# Unsigned 1.0.0.24 steady-state client.
# Tick asks the control service for a challenge, then heartbeats, polls, gets, and posts results.
# The device base is the hash-pinned winrtcs_device.cfg. The task environment is not a base source.
# The server row is authoritative. A local mode file is not.
# Certificate validation stays on. Revocation stays on except the named lab host when the lab fixture sets WINRTCS_LAB_REVOCATION=skip.
# No shared bearer. No validation callback.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Admit', 'Prove', 'RunHarmless', 'Tick', 'PreserveGuid', 'HttpOp')]
    [string]$Action,
    [string]$WorkDir = '',
    [string]$Case = ''
)

$ErrorActionPreference = 'Stop'

if ($null -ne [Net.ServicePointManager]::ServerCertificateValidationCallback) {
    throw 'tls-validation-callback-present'
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $text = [IO.File]::ReadAllText($Path)
    return ($text | ConvertFrom-Json)
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    $json = $Value | ConvertTo-Json -Compress -Depth 6
    $utf8 = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllText($Path, $json, $utf8)
}

function Write-StatusText {
    param([Parameter(Mandatory = $true)][string]$Json)
    if (-not $WorkDir) { throw 'workdir-required' }
    $utf8 = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllText((Join-Path $WorkDir 'tick-status.json'), $Json, $utf8)
}

function Convert-StandardBase64 {
    param([Parameter(Mandatory = $true)][string]$Text)
    return [Convert]::FromBase64String($Text)
}

function Get-Base64UrlNonce {
    $buffer = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) }
    finally { $rng.Dispose() }
    $encoded = [Convert]::ToBase64String($buffer).TrimEnd('=')
    return $encoded.Replace('+', '-').Replace('/', '_')
}

function Get-UnixTime {
    $origin = New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)
    return [int64]([DateTime]::UtcNow - $origin).TotalSeconds
}

function Get-AsciiSha256Hex {
    param([Parameter(Mandatory = $true)][string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($Text)) }
    finally { $sha.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-Rsa {
    param([Parameter(Mandatory = $true)]$Material)
    $parameters = New-Object Security.Cryptography.RSAParameters
    $parameters.Modulus = Convert-StandardBase64 $Material.modulus
    $parameters.Exponent = Convert-StandardBase64 $Material.exponent
    $parameters.D = Convert-StandardBase64 $Material.d
    $parameters.P = Convert-StandardBase64 $Material.p
    $parameters.Q = Convert-StandardBase64 $Material.q
    $parameters.DP = Convert-StandardBase64 $Material.dp
    $parameters.DQ = Convert-StandardBase64 $Material.dq
    $parameters.InverseQ = Convert-StandardBase64 $Material.inverseq
    if ('System.Security.Cryptography.RSACng' -as [type]) {
        $rsa = New-Object Security.Cryptography.RSACng
        $rsa.ImportParameters($parameters)
        return $rsa
    }
    $csp = New-Object Security.Cryptography.CspParameters 24
    $csp.Flags = [Security.Cryptography.CspProviderFlags]::CreateEphemeralKey
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider 2048, $csp
    $rsa.PersistKeyInCsp = $false
    $rsa.ImportParameters($parameters)
    return $rsa
}

function Get-Pkcs1Signature {
    param(
        [Parameter(Mandatory = $true)]$Material,
        [Parameter(Mandatory = $true)][byte[]]$Message
    )
    $rsa = Get-Rsa $Material
    try {
        if ($rsa -is [Security.Cryptography.RSACng]) {
            return [Convert]::ToBase64String(
                $rsa.SignData(
                    $Message,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.RSASignaturePadding]::Pkcs1
                )
            )
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return [Convert]::ToBase64String($rsa.SignData($Message, $sha)) }
        finally { $sha.Dispose() }
    }
    finally {
        if ($rsa -is [Security.Cryptography.RSACng]) { $rsa.Dispose() }
        else { $rsa.Clear() }
    }
}

function Assert-NoSharedSecret {
    if ($env:WINRTCS_DEVICE_BEARER) { throw 'bearer-fallback-denied' }
}

function Get-PinnedDeviceBase {
    $cfgPath = 'C:\ProgramData\WinRTCS\winrtcs_device.cfg'
    $manifestPath = 'C:\ProgramData\WinRTCS\winrtcs.version'
    if (-not (Test-Path -LiteralPath $cfgPath) -or -not (Test-Path -LiteralPath $manifestPath)) {
        throw 'endpoint-not-configured'
    }
    $pin = ''
    foreach ($line in [IO.File]::ReadAllLines($manifestPath)) {
        if ($line.StartsWith('CONFIG_SHA256=')) { $pin = $line.Substring(14).Trim().ToLowerInvariant() }
    }
    if ($pin.Length -ne 64) { throw 'endpoint-not-configured' }
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::Open($cfgPath, 'Open', 'Read', 'Read')
    try { $got = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
    if ($got -ne $pin) { throw 'endpoint-not-configured' }
    $text = [IO.File]::ReadAllText($cfgPath).Trim()
    if ($text -match '(?i)bearer|token|private|k=') { throw 'endpoint-not-configured' }
    if ($text -notmatch '\ADEVICE_BASE=(https://[A-Za-z0-9.-]+)/?\z') { throw 'endpoint-not-configured' }
    return $Matches[1].TrimEnd('/')
}

function Enable-DeviceTls {
    if ($null -ne [Net.ServicePointManager]::ServerCertificateValidationCallback) {
        throw 'tls-validation-callback-present'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::Expect100Continue = $false
    $base = Get-PinnedDeviceBase
    if ($base -notmatch '\Ahttps://') { throw 'control-endpoint-must-be-https' }
    $uri = [Uri]$base
    $labHost = ($uri.Scheme -eq 'https' -and $uri.Host -eq 'winrtcs-device-lab.invalid')
    if ($labHost -and $env:WINRTCS_LAB_REVOCATION -eq 'skip') {
        [Net.ServicePointManager]::CheckCertificateRevocationList = $false
    }
    else {
        [Net.ServicePointManager]::CheckCertificateRevocationList = $true
    }
}

function Get-AdmissionRaw {
    param($Identity, [string]$Method, [string]$Target, [byte[]]$Body)
    if ($null -eq $Body -or $Body.Length -eq 0) { $bodyB64 = '' }
    else { $bodyB64 = [Convert]::ToBase64String($Body) }
    return '{"host":"' + $Identity.host + '","mid":"' + $Identity.mid + '","keyfp":"' + $Identity.keyfp + '","epoch":' + [string]$Identity.epoch + ',"generation":"' + $Identity.generation + '","method":"' + $Method + '","target":"' + $Target + '","body_b64":"' + $bodyB64 + '"}'
}

function Get-HeartbeatRaw {
    param($Identity)
    return '{"host":"' + $Identity.host + '","mid":"' + $Identity.mid + '","generation":"' + $Identity.generation + '"}'
}

function Get-ResultRaw {
    param($Identity, [string]$CommandId, [string]$Lease, [int]$Rc, [string]$Out)
    return '{"host":"' + $Identity.host + '","mid":"' + $Identity.mid + '","id":' + $CommandId + ',"lease":"' + $Lease + '","rc":' + $Rc + ',"out":"' + $Out + '"}'
}

function Get-PollTarget {
    param($Identity)
    return '/cmd/poll?host=' + [Uri]::EscapeDataString([string]$Identity.host) + '&mid=' + [Uri]::EscapeDataString([string]$Identity.mid)
}

function Get-GetTarget {
    param($Identity, [string]$CommandId, [string]$Lease)
    return '/cmd/get?host=' + [Uri]::EscapeDataString([string]$Identity.host) +
        '&id=' + [Uri]::EscapeDataString($CommandId) +
        '&lease=' + [Uri]::EscapeDataString($Lease) +
        '&mid=' + [Uri]::EscapeDataString([string]$Identity.mid)
}

function Invoke-Control {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Target,
        [byte[]]$Body,
        [Parameter(Mandatory = $true)]$Headers,
        [string]$Endpoint = ''
    )
    if (-not $Body) { $Body = New-Object byte[] 0 }
    $primary = (Get-PinnedDeviceBase).TrimEnd('/')
    $fallback = 'https://device.wirbe.com'
    $base = $(if ($Endpoint) { $Endpoint.TrimEnd('/') } else { $primary })
    $transportPath = 'C:\ProgramData\WinRTCS\device-transport.txt'
    [IO.File]::WriteAllText($transportPath, $(if ($Endpoint) { 'fallback' } else { 'primary' }))
    $request = [Net.HttpWebRequest]::Create([Uri]($base + $Target))
    $request.Method = $Method
    $request.Timeout = 20000
    $request.ReadWriteTimeout = 20000
    $request.AllowAutoRedirect = $false
    $request.KeepAlive = $false
    foreach ($name in @($Headers.Keys)) {
        $value = [string]$Headers[$name]
        if ($name -eq 'Content-Type') { $request.ContentType = $value }
        else { [void]$request.Headers.Set($name, $value) }
    }
    $status = 0
    $text = ''
    try {
        if ($Method -eq 'POST') {
            $request.ContentLength = $Body.Length
            $stream = $request.GetRequestStream()
            try {
                if ($Body.Length -gt 0) { $stream.Write($Body, 0, $Body.Length) }
            }
            finally { $stream.Close() }
        }
        $response = $request.GetResponse()
        try {
            $status = [int]$response.StatusCode
            $reader = New-Object IO.StreamReader($response.GetResponseStream(), [Text.Encoding]::UTF8)
            try { $text = $reader.ReadToEnd() }
            finally { $reader.Close() }
        }
        finally { $response.Close() }
    }
    catch [Net.WebException] {
        $web = $_.Exception
        $response = $web.Response
        if (-not $response) {
            $transport = @('NameResolutionFailure', 'ConnectFailure', 'Timeout', 'ReceiveFailure', 'SendFailure', 'ConnectionClosed', 'ProxyNameResolutionFailure', 'TrustFailure', 'SecureChannelFailure')
            if (-not $Endpoint -and ($transport -contains [string]$web.Status)) {
                return Invoke-Control -Method $Method -Target $Target -Body $Body -Headers $Headers -Endpoint $fallback
            }
            throw
        }
        $status = [int]$response.StatusCode
        if (-not $Endpoint -and ($status -eq 502 -or $status -eq 503 -or $status -eq 504)) {
            $response.Close()
            return Invoke-Control -Method $Method -Target $Target -Body $Body -Headers $Headers -Endpoint $fallback
        }
        try {
            $status = [int]$response.StatusCode
            $reader = New-Object IO.StreamReader($response.GetResponseStream(), [Text.Encoding]::UTF8)
            try { $text = $reader.ReadToEnd() }
            finally { $reader.Close() }
        }
        finally { $response.Close() }
    }
    return @{ Status = $status; Body = $text }
}

function Invoke-Prepare {
    param($Identity, $Material, [string]$Method, [string]$Target, [byte[]]$Body)
    $raw = Get-AdmissionRaw $Identity $Method $Target $Body
    $nonce = Get-Base64UrlNonce
    $stamp = Get-UnixTime
    $message = "WINRTCS_CHALLENGE_ADMISSION_V1`nwinrtcs-device-control-lab`n" + (Get-AsciiSha256Hex $raw) + "`n" + $nonce + "`n" + $stamp + "`n"
    $proof = Get-Pkcs1Signature $Material ([Text.Encoding]::ASCII.GetBytes($message))
    $admissionHeaders = @{
        'Content-Type' = 'application/json'
        'X-WinRTCS-Admission-Nonce' = $nonce
        'X-WinRTCS-Admission-Time' = [string]$stamp
        'X-WinRTCS-Admission-Proof' = $proof
    }
    $admitted = Invoke-Control 'POST' '/device/control/challenge' ([Text.Encoding]::ASCII.GetBytes($raw)) $admissionHeaders
    if ($admitted.Status -ne 200) {
        return @{ Status = $admitted.Status; Headers = $null; Challenge = $null }
    }
    $challenge = $admitted.Body | ConvertFrom-Json
    $signed = Get-Pkcs1Signature $Material ([Convert]::FromBase64String([string]$challenge.message_b64))
    $headers = @{
        'X-WinRTCS-Host' = [string]$Identity.host
        'X-WinRTCS-Mid' = [string]$Identity.mid
        'X-WinRTCS-Keyfp' = [string]$Identity.keyfp
        'X-WinRTCS-Epoch' = [string]$Identity.epoch
        'X-WinRTCS-Generation' = [string]$Identity.generation
        'X-WinRTCS-Nonce' = [string]$challenge.nonce
        'X-WinRTCS-Proof' = $signed
    }
    if ($Method -eq 'POST') { $headers['Content-Type'] = 'application/json' }
    return @{ Status = 200; Headers = $headers; Challenge = $challenge }
}

function Invoke-Bound {
    param($Identity, $Material, [string]$Method, [string]$Target, [byte[]]$Body)
    $prepared = Invoke-Prepare $Identity $Material $Method $Target $Body
    if ($prepared.Status -ne 200) { return $prepared }
    $done = Invoke-Control $Method $Target $Body $prepared.Headers
    return @{ Status = $done.Status; Body = $done.Body; Headers = $prepared.Headers }
}

function Get-EmptyBody {
    return (New-Object byte[] 0)
}

if ($Action -eq 'PreserveGuid') {
    if (-not $WorkDir) { throw 'workdir-required' }
    $guid = [string](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    if ($guid -notmatch '\A[0-9a-fA-F-]{36}\z') { throw 'guid-unreadable' }
    $path = Join-Path $WorkDir 'machine.guid'
    $utf8 = New-Object Text.UTF8Encoding $false
    if (Test-Path -LiteralPath $path) {
        $existing = [IO.File]::ReadAllText($path).Trim()
        if ($existing -cne $guid) { throw 'guid-changed' }
    }
    else {
        [IO.File]::WriteAllText($path, $guid, $utf8)
    }
    Write-Output 'GUID_PRESERVED=1'
    exit 0
}

if ($Action -eq 'RunHarmless') {
    if (-not $WorkDir) { throw 'workdir-required' }
    Assert-NoSharedSecret
    $command = [IO.File]::ReadAllText((Join-Path $WorkDir 'command.txt')).TrimEnd("`r", "`n")
    if ($command -cne 'echo ok' -and $command -cne 'keeper-recheck' -and $command -cne 'health-snapshot') { throw 'command-not-allowlisted' }
    if ($command -ceq 'echo ok') {
        $output = & cmd.exe /c echo ok
        if ($LASTEXITCODE -ne 0) { throw 'harmless-command-failed' }
        $text = (($output | Out-String).Trim())
    } else { $text = $command }
    $utf8 = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllText((Join-Path $WorkDir 'harmless-out.txt'), $text, $utf8)
    Write-Output 'HARMLESS_RC=0'
    exit 0
}

if ($Action -eq 'Admit') {
    if (-not $WorkDir) { throw 'workdir-required' }
    $identity = Read-JsonFile (Join-Path $WorkDir 'identity.json')
    $material = Read-JsonFile (Join-Path $WorkDir 'key.json')
    Assert-NoSharedSecret
    $method = [IO.File]::ReadAllText((Join-Path $WorkDir 'method.txt')).Trim()
    $target = [IO.File]::ReadAllText((Join-Path $WorkDir 'target.txt')).Trim()
    $body = [IO.File]::ReadAllBytes((Join-Path $WorkDir 'body.bin'))
    $raw = Get-AdmissionRaw $identity $method $target $body
    $nonce = Get-Base64UrlNonce
    $stamp = Get-UnixTime
    $message = "WINRTCS_CHALLENGE_ADMISSION_V1`nwinrtcs-device-control-lab`n" + (Get-AsciiSha256Hex $raw) + "`n" + $nonce + "`n" + $stamp + "`n"
    $proof = Get-Pkcs1Signature $material ([Text.Encoding]::ASCII.GetBytes($message))
    Write-JsonFile (Join-Path $WorkDir 'admission.json') ([PSCustomObject]@{
        raw = $raw
        nonce = $nonce
        time = [string]$stamp
        proof = $proof
    })
    Write-Output 'ADMIT_OK=1'
    exit 0
}

if ($Action -eq 'Prove') {
    if (-not $WorkDir) { throw 'workdir-required' }
    $material = Read-JsonFile (Join-Path $WorkDir 'key.json')
    Assert-NoSharedSecret
    $challenge = Read-JsonFile (Join-Path $WorkDir 'challenge.json')
    $proof = Get-Pkcs1Signature $material ([Convert]::FromBase64String([string]$challenge.message_b64))
    Write-JsonFile (Join-Path $WorkDir 'proof.json') ([PSCustomObject]@{
        nonce = [string]$challenge.nonce
        proof = $proof
    })
    Write-Output 'PROVE_OK=1'
    exit 0
}

if (-not $WorkDir) { throw 'workdir-required' }
Assert-NoSharedSecret
Enable-DeviceTls
$identity = Read-JsonFile (Join-Path $WorkDir 'identity.json')
$material = Read-JsonFile (Join-Path $WorkDir 'key.json')

if ($Action -eq 'HttpOp') {
    $empty = Get-EmptyBody
    $heartbeat = [Text.Encoding]::ASCII.GetBytes((Get-HeartbeatRaw $identity))
    if ($Case -eq 'heartbeat') {
        $done = Invoke-Bound $identity $material 'POST' '/heartbeat' $heartbeat
        Write-StatusText ('{"status":' + $done.Status + '}')
        Write-Output ('HTTPOP=heartbeat:' + $done.Status)
        exit 0
    }
    if ($Case -eq 'replay') {
        $done = Invoke-Bound $identity $material 'POST' '/heartbeat' $heartbeat
        $again = Invoke-Control 'POST' '/heartbeat' $heartbeat $done.Headers
        Write-StatusText ('{"first":' + $done.Status + ',"second":' + $again.Status + '}')
        Write-Output ('HTTPOP=replay:' + $done.Status + ':' + $again.Status)
        exit 0
    }
    if ($Case -eq 'cross-op') {
        $prepared = Invoke-Prepare $identity $material 'POST' '/heartbeat' $heartbeat
        if ($prepared.Status -ne 200) { throw 'cross-op-prepare-failed' }
        $headers = @{}
        foreach ($name in @($prepared.Headers.Keys)) {
            if ($name -ne 'Content-Type') { $headers[$name] = $prepared.Headers[$name] }
        }
        $sent = Invoke-Control 'GET' (Get-PollTarget $identity) $empty $headers
        Write-StatusText ('{"status":' + $sent.Status + '}')
        Write-Output ('HTTPOP=cross-op:' + $sent.Status)
        exit 0
    }
    if ($Case -eq 'prepare') {
        $prepared = Invoke-Prepare $identity $material 'POST' '/heartbeat' $heartbeat
        if ($prepared.Status -ne 200) {
            Write-StatusText ('{"status":' + $prepared.Status + '}')
            Write-Output ('HTTPOP=prepare:' + $prepared.Status)
            exit 0
        }
        $utf8 = New-Object Text.UTF8Encoding $false
        $headerJson = '{"method":"POST","target":"/heartbeat","body_b64":"' + [Convert]::ToBase64String($heartbeat) + '"'
        foreach ($name in @('X-WinRTCS-Host','X-WinRTCS-Mid','X-WinRTCS-Keyfp','X-WinRTCS-Epoch','X-WinRTCS-Generation','X-WinRTCS-Nonce','X-WinRTCS-Proof')) {
            $headerJson += ',"' + $name + '":"' + [string]$prepared.Headers[$name] + '"'
        }
        $headerJson += '}'
        [IO.File]::WriteAllText((Join-Path $WorkDir 'saved-op.json'), $headerJson, $utf8)
        Write-StatusText '{"status":200}'
        Write-Output 'HTTPOP=prepare:200'
        exit 0
    }
    if ($Case -eq 'submit-saved') {
        $saved = Read-JsonFile (Join-Path $WorkDir 'saved-op.json')
        $headers = @{
            'Content-Type' = 'application/json'
            'X-WinRTCS-Host' = [string]$saved.'X-WinRTCS-Host'
            'X-WinRTCS-Mid' = [string]$saved.'X-WinRTCS-Mid'
            'X-WinRTCS-Keyfp' = [string]$saved.'X-WinRTCS-Keyfp'
            'X-WinRTCS-Epoch' = [string]$saved.'X-WinRTCS-Epoch'
            'X-WinRTCS-Generation' = [string]$saved.'X-WinRTCS-Generation'
            'X-WinRTCS-Nonce' = [string]$saved.'X-WinRTCS-Nonce'
            'X-WinRTCS-Proof' = [string]$saved.'X-WinRTCS-Proof'
        }
        $body = [Convert]::FromBase64String([string]$saved.body_b64)
        $done = Invoke-Control ([string]$saved.method) ([string]$saved.target) $body $headers
        Write-StatusText ('{"status":' + $done.Status + '}')
        Write-Output ('HTTPOP=submit-saved:' + $done.Status)
        exit 0
    }
    if ($Case -eq 'challenge-burst') {
        $count = [int]([IO.File]::ReadAllText((Join-Path $WorkDir 'burst-count.txt')).Trim())
        $ok = 0
        $last = 0
        for ($i = 0; $i -lt $count; $i++) {
            $prepared = Invoke-Prepare $identity $material 'POST' '/heartbeat' $heartbeat
            $last = [int]$prepared.Status
            if ($last -eq 200) { $ok += 1 } else { break }
        }
        Write-StatusText ('{"ok":' + $ok + ',"last":' + $last + '}')
        Write-Output ('HTTPOP=challenge-burst:' + $ok + ':' + $last)
        exit 0
    }
    if ($Case -eq 'poll-get') {
        $beat = Invoke-Bound $identity $material 'POST' '/heartbeat' $heartbeat
        if ($beat.Status -ne 200) { throw 'poll-get-heartbeat-failed' }
        $poll = Invoke-Bound $identity $material 'GET' (Get-PollTarget $identity) $empty
        if ($poll.Status -ne 200) { throw 'poll-get-poll-failed' }
        $polled = $poll.Body | ConvertFrom-Json
        if (-not $polled.command_id) { throw 'poll-get-no-command' }
        $commandId = [string]$polled.command_id
        $lease = [string]$polled.lease
        $utf8 = New-Object Text.UTF8Encoding $false
        [IO.File]::WriteAllText((Join-Path $WorkDir 'saved-command-id.txt'), $commandId, $utf8)
        [IO.File]::WriteAllText((Join-Path $WorkDir 'saved-lease.txt'), $lease, $utf8)
        $got = Invoke-Bound $identity $material 'GET' (Get-GetTarget $identity $commandId $lease) $empty
        Write-StatusText ('{"heartbeat":' + $beat.Status + ',"poll":' + $poll.Status + ',"get":' + $got.Status + '}')
        Write-Output ('HTTPOP=poll-get:' + $got.Status)
        exit 0
    }
    if ($Case -eq 'result') {
        $commandId = [IO.File]::ReadAllText((Join-Path $WorkDir 'saved-command-id.txt')).Trim()
        $lease = [IO.File]::ReadAllText((Join-Path $WorkDir 'saved-lease.txt')).Trim()
        $out = 'ok'
        $rc = 0
        $outPath = Join-Path $WorkDir 'result-out.txt'
        $rcPath = Join-Path $WorkDir 'result-rc.txt'
        if (Test-Path -LiteralPath $outPath) { $out = [IO.File]::ReadAllText($outPath).Trim() }
        if (Test-Path -LiteralPath $rcPath) { $rc = [int]([IO.File]::ReadAllText($rcPath).Trim()) }
        $raw = Get-ResultRaw $identity $commandId $lease $rc $out
        $done = Invoke-Bound $identity $material 'POST' '/cmd/result' ([Text.Encoding]::ASCII.GetBytes($raw))
        $idempotent = 'false'
        if ($done.Status -eq 200 -and $done.Body) {
            $parsed = $done.Body | ConvertFrom-Json
            if ($parsed.idempotent -eq $true) { $idempotent = 'true' }
        }
        Write-StatusText ('{"status":' + $done.Status + ',"idempotent":' + $idempotent + '}')
        Write-Output ('HTTPOP=result:' + $done.Status + ':' + $idempotent)
        exit 0
    }
    throw 'unknown-httpop'
}

function Get-VersionGeneration {
    $versionPath = Join-Path $WorkDir 'winrtcs.version'
    if (-not (Test-Path -LiteralPath $versionPath)) { return '' }
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::Open($versionPath, 'Open', 'Read', 'Read')
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Update-IdentityGeneration {
    param([Parameter(Mandatory = $true)][string]$Generation)
    $path = Join-Path $WorkDir 'identity.json'
    $utf8 = New-Object Text.UTF8Encoding $false
    $text = [IO.File]::ReadAllText($path)
    $next = [regex]::Replace($text, '"generation"\s*:\s*"[0-9a-f]{64}"', '"generation":"' + $Generation + '"', 1)
    if ($next -eq $text) { throw 'identity-generation-unchanged' }
    [IO.File]::WriteAllText($path, $next, $utf8)
}

if ($Action -eq 'Tick') {
    try {
    $fileGeneration = Get-VersionGeneration
    if ($fileGeneration.Length -eq 64 -and [string]$identity.generation -ne $fileGeneration) {
        $handoffBody = [Text.Encoding]::ASCII.GetBytes('{"generation":"' + $fileGeneration + '"}')
        $handed = Invoke-Bound $identity $material 'POST' '/generation/handoff' $handoffBody
        if ($handed.Status -ne 200) { throw 'generation-handoff-failed' }
        $handedParsed = $handed.Body | ConvertFrom-Json
        if ([string]$handedParsed.generation -ne $fileGeneration) { throw 'generation-handoff-mismatch' }
        Update-IdentityGeneration $fileGeneration
        $identity = Read-JsonFile (Join-Path $WorkDir 'identity.json')
    }
    $pendingPath = Join-Path $WorkDir 'pending-result.json'
    $pendingStatus = 0
    if (Test-Path -LiteralPath $pendingPath) {
        $pending = [IO.File]::ReadAllBytes($pendingPath)
        $retried = Invoke-Bound $identity $material 'POST' '/cmd/result' $pending
        $pendingStatus = [int]$retried.Status
        if ($pendingStatus -eq 200) { Remove-Item -LiteralPath $pendingPath -Force }
    }
    $heartbeat = [Text.Encoding]::ASCII.GetBytes((Get-HeartbeatRaw $identity))
    $beat = Invoke-Bound $identity $material 'POST' '/heartbeat' $heartbeat
    $marker = Join-Path $WorkDir 'device-active.marker'
    if ($beat.Status -eq 403 -and (Test-Path -LiteralPath $marker)) {
        Start-Sleep -Seconds 1
        $beat = Invoke-Bound $identity $material 'POST' '/heartbeat' $heartbeat
    }
    if ($beat.Status -eq 403 -and -not (Test-Path -LiteralPath $marker)) {
        Write-StatusText ('{"transition":"legacy-not-prepared","heartbeat":403,"pending":' + $pendingStatus + '}')
        Write-Output 'DEVICE_TICK=legacy-not-prepared'
        exit 0
    }
    if ($beat.Status -ne 200) {
        Write-StatusText ('{"transition":"heartbeat-denied","heartbeat":' + $beat.Status + ',"pending":' + $pendingStatus + '}')
        Write-Output 'DEVICE_TICK=heartbeat-denied'
        exit 4
    }
    $utf8 = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllText($marker, 'ACTIVE', $utf8)
    $empty = Get-EmptyBody
    $poll = Invoke-Bound $identity $material 'GET' (Get-PollTarget $identity) $empty
    $getStatus = 0
    $resultStatus = 0
    $retryStatus = 0
    $idempotent = 'false'
    if ($poll.Status -eq 200 -and $poll.Body) {
        $polled = $poll.Body | ConvertFrom-Json
        if ($polled.command_id) {
            $commandId = [string]$polled.command_id
            $lease = [string]$polled.lease
            $got = Invoke-Bound $identity $material 'GET' (Get-GetTarget $identity $commandId $lease) $empty
            $getStatus = [int]$got.Status
            if ($getStatus -eq 200) {
                $cmd = [string](($got.Body | ConvertFrom-Json).cmd_text)
                $allowed = $cmd -ceq 'echo ok' -or $cmd -ceq 'keeper-recheck' -or $cmd -ceq 'health-snapshot'
                if (-not $allowed) {
                    $resultRaw = Get-ResultRaw $identity $commandId $lease 1 'rejected'
                    $resultBody = [Text.Encoding]::ASCII.GetBytes($resultRaw)
                    $posted = Invoke-Bound $identity $material 'POST' '/cmd/result' $resultBody
                    $resultStatus = [int]$posted.Status
                } elseif ($cmd -ceq 'echo ok') {
                    $output = & cmd.exe /c echo ok
                    if ($LASTEXITCODE -ne 0) { throw 'harmless-command-failed' }
                    if ((($output | Out-String).Trim()) -cne 'ok') { throw 'harmless-output-mismatch' }
                    $resultRaw = Get-ResultRaw $identity $commandId $lease 0 'ok'
                    $resultBody = [Text.Encoding]::ASCII.GetBytes($resultRaw)
                    $posted = Invoke-Bound $identity $material 'POST' '/cmd/result' $resultBody
                    $resultStatus = [int]$posted.Status
                    $again = Invoke-Bound $identity $material 'POST' '/cmd/result' $resultBody
                    $retryStatus = [int]$again.Status
                    if ($again.Status -eq 200 -and $again.Body) {
                        $parsed = $again.Body | ConvertFrom-Json
                        if ($parsed.idempotent -eq $true) { $idempotent = 'true' }
                    }
                    [IO.File]::WriteAllText((Join-Path $WorkDir 'last-result.json'), $resultRaw, $utf8)
                } else {
                    if ($cmd -ceq 'keeper-recheck') {
                        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\ProgramData\WinRTCS\winrtcs_keeper.ps1' -Action Ensure | Out-Null
                    }
                    $resultRaw = Get-ResultRaw $identity $commandId $lease 0 $cmd
                    $resultBody = [Text.Encoding]::ASCII.GetBytes($resultRaw)
                    $posted = Invoke-Bound $identity $material 'POST' '/cmd/result' $resultBody
                    $resultStatus = [int]$posted.Status
                    [IO.File]::WriteAllText((Join-Path $WorkDir 'last-result.json'), $resultRaw, $utf8)
                }
            }
        }
    }
    Write-StatusText ('{"transition":"active","heartbeat":' + $beat.Status + ',"poll":' + $poll.Status + ',"get":' + $getStatus + ',"result":' + $resultStatus + ',"retry":' + $retryStatus + ',"idempotent":' + $idempotent + ',"pending":' + $pendingStatus + '}')
    $versionPath = Join-Path $WorkDir 'winrtcs.version'
    $generation = 'none'
    if (Test-Path -LiteralPath $versionPath) {
        $sha = [Security.Cryptography.SHA256]::Create()
        $stream = [IO.File]::Open($versionPath, 'Open', 'Read', 'Read')
        try { $generation = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $stream.Dispose(); $sha.Dispose() }
    }
    $markerText = "ver=1.0.0.13`r`ngeneration=$generation`r`nstage=active`r`nunix=" + (Get-UnixTime) + "`r`n"
    [IO.File]::WriteAllText((Join-Path $WorkDir 'continuity.txt'), $markerText, (New-Object Text.UTF8Encoding $false))
    $failPath = Join-Path $WorkDir 'continuity-failure.txt'
    if (Test-Path -LiteralPath $failPath) { Remove-Item -LiteralPath $failPath -Force }
    Write-Output 'DEVICE_TICK=active'
    exit 0
    }
    catch {
        $msg = [string]$_.Exception.Message
        if ($msg.Length -gt 140) { $msg = $msg.Substring(0, 140) }
        $msg = $msg -replace '[A-Za-z0-9+/=]{24,}', 'redacted'
        $utf8 = New-Object Text.UTF8Encoding $false
        [IO.File]::WriteAllText((Join-Path $WorkDir 'continuity-failure.txt'), $msg, $utf8)
        Write-Output ('DEVICE_TICK=error:' + $msg)
        exit 4
    }
}

throw 'unknown-action'
