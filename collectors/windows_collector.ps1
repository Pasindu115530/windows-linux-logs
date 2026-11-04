# Run as Administrator or SYSTEM on an authorized TEST computer.
param(
    [ValidateSet('win01','win02')][string]$MachineId,
    [string]$ApiBase,
    [string]$KeyFile = 'C:\ProgramData\AccessReview\agent.key',
    [string]$StateFile = 'C:\ProgramData\AccessReview\state.txt'
)
$ErrorActionPreference = 'Stop'
$key = (Get-Content -LiteralPath $KeyFile -Raw).Trim()
$base = $ApiBase.TrimEnd('/')
$headers = @{ 'X-Agent-Key' = $key }
function Send-Json([string]$endpoint, [object]$payload) {
    $body = ConvertTo-Json -InputObject $payload -Depth 8 -Compress
    Invoke-RestMethod -Uri "$base$endpoint" -Method POST -Headers $headers -Body $body -ContentType 'application/json' -TimeoutSec 30 | Out-Null
}

# Local accounts only. Domain accounts and nested AD memberships need another connector.
$admins = @{}
try {
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    foreach ($m in (Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop)) {
        $admins[$m.Name.Split('\')[-1].ToLowerInvariant()] = $true
    }
} catch { Write-Warning "Admin membership collection incomplete: $_" }
$accounts = @(
  Get-LocalUser | ForEach-Object {
    $last = $null
    if ($_.LastLogon) { $last = $_.LastLogon.ToUniversalTime().ToString('o') }
    @{
      username = $_.Name
      enabled = [bool]$_.Enabled
      is_admin = [bool]$admins.ContainsKey($_.Name.ToLowerInvariant())
      last_login_at = $last
    }
  }
)
Send-Json '/api/ingest/snapshot' @{
  machine_id=$MachineId
  collected_at=[DateTime]::UtcNow.ToString('o')
  accounts=$accounts
}

$previous = [long]0
if (Test-Path -LiteralPath $StateFile) {
    $raw = (Get-Content -LiteralPath $StateFile -Raw).Trim()
    if ($raw) { $previous = [long]$raw }
}
# Initial run considers the previous 24 hours; subsequent runs use event record IDs.
# For demonstration-sized machines, first 5000 new events will be sufficient.
$filter = @{LogName='Security';Id=@(4624,4625);StartTime=(Get-Date).AddDays(-1)}
try {
    $rawEvents = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 5000 -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') { $rawEvents=@() }
    else { throw }
}
$selected = @($rawEvents | Where-Object { $_.RecordId -gt $previous } | Sort-Object RecordId)
$batch = New-Object System.Collections.ArrayList
$highWater = $previous
foreach ($event in $selected) {
    [xml]$doc = $event.ToXml()
    $fields = @{}
    foreach ($field in $doc.Event.EventData.Data) {
        if ($field.Name) { $fields[$field.Name] = [string]$field.'#text' }
    }
    $username = [string]$fields['TargetUserName']
    $logonType = [string]$fields['LogonType']
    $highWater = [long]$event.RecordId
    # Interactive / unlock / remote-interactive login; also network login failures.
    $allowed = if ($event.Id -eq 4624) { @('2','7','10','11') } else { @('2','3','10','11') }
    if (($allowed -notcontains $logonType) -or $username -eq '' -or
        $username.EndsWith('$') -or $username -in @('SYSTEM','ANONYMOUS LOGON','LOCAL SERVICE','NETWORK SERVICE')) { continue }
    [void]$batch.Add(@{
        event_uid = "Security:$($event.RecordId)"
        username = $username
        event_type = $(if ($event.Id -eq 4624) { 'login_success' } else { 'login_failure' })
        occurred_at = $event.TimeCreated.ToUniversalTime().ToString('o')
        details = @{ windows_event_id = $event.Id; logon_type = $logonType; target_domain = [string]$fields["TargetDomainName"]; local_account = ([string]$fields["TargetDomainName"] -eq $env:COMPUTERNAME) }
    })
    if ($batch.Count -ge 100) {
        Send-Json '/api/ingest/events' @{machine_id=$MachineId;events=@($batch.ToArray())}
        $batch.Clear()
    }
}
if ($batch.Count -gt 0) {
    Send-Json '/api/ingest/events' @{machine_id=$MachineId;events=@($batch.ToArray())}
}
# All HTTP requests completed before state is advanced. Duplicates are safe on retry.
if ($highWater -gt $previous) { Set-Content -LiteralPath $StateFile -Value $highWater -NoNewline }
Write-Host "[$MachineId] inventory sent; $($selected.Count) log records examined."
