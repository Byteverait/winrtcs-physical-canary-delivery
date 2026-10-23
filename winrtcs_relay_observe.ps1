# Record relay transport facts. TCP success is not an authenticated session.
$ErrorActionPreference = 'Stop'
$allowed = @('YOSSI-2018', 'YAFA-HP', 'WARCO')
if ($allowed -notcontains $env:COMPUTERNAME) {
    Write-Output 'SCOPE_REFUSED=NOT_OBSERVATION_HOST'
    exit 2
}
$targets = @(
    @{ Name = 'PULSV'; Host = 'service.pulsv.com' },
    @{ Name = 'SECZIO'; Host = 'service.seczio.com' }
)
$root = 'C:\ProgramData\WinRTCS\recovery'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$path = Join-Path $root 'relay-observation.txt'
$observed = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$lines = New-Object System.Collections.Generic.List[string]
[void]$lines.Add('observed_at=' + $observed)
[void]$lines.Add('fresh_for_seconds=300')
[void]$lines.Add('computer=' + $env:COMPUTERNAME)
Write-Output ('OBSERVED_AT=' + $observed)
foreach ($target in $targets) {
    $dns = ''
    try {
        $answers = [Net.Dns]::GetHostAddresses([string]$target.Host)
        $dns = (($answers | ForEach-Object { $_.IPAddressToString }) -join ',')
    } catch {
        $dns = 'DNS_FAILED'
    }
    $tcp = $false
    try {
        $client = New-Object Net.Sockets.TcpClient
        $async = $client.BeginConnect([string]$target.Host, 443, $null, $null)
        $tcp = $async.AsyncWaitHandle.WaitOne(8000, $false) -and $client.Connected
        $client.Close()
    } catch {
        $tcp = $false
    }
    [void]$lines.Add('name=' + $target.Name)
    [void]$lines.Add('dns=' + $dns)
    [void]$lines.Add('tcp=' + $tcp)
    [void]$lines.Add('application=UNVERIFIED')
    Write-Output ('RELAY=' + $target.Name + ' DNS=' + $dns + ' TCP=' + $tcp + ' APPLICATION=UNVERIFIED')
}
[IO.File]::WriteAllLines($path, $lines)
Write-Output 'RELAY_FIELD=OBSERVED'
Write-Output 'KEEPER_RELAY_FIELD=not_checked'
Write-Output 'KEEPER=NOT_CALLED'
Write-Output 'REBOOT=NOT_CALLED'
exit 0
