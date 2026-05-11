#requires -version 5.1
<#
PingReports Windows agent installer.

  Set-ExecutionPolicy -Scope Process Bypass; `
    $env:PR_AGENT_ID='<uuid>'; $env:PR_AGENT_TOKEN='<token>'; `
    irm https://raw.githubusercontent.com/PingReports/windows-agent/main/install.ps1 | iex

Requires an elevated PowerShell. Drops agent.ps1 into
%ProgramData%\PingReportsAgent\, writes agent.conf with the supplied env,
registers a Scheduled Task that fires every 5 minutes as SYSTEM, runs the
agent once immediately to surface auth/connectivity errors.
#>

[CmdletBinding()]
param(
    [string]$AgentId    = $env:PR_AGENT_ID,
    [string]$AgentToken = $env:PR_AGENT_TOKEN,
    [string]$IngestUrl  = $(if ($env:PR_INGEST_URL) { $env:PR_INGEST_URL } else { 'https://agents.pingreports.com/v1/ingest' }),
    [string]$AgentName  = $(if ($env:PR_AGENT_NAME) { $env:PR_AGENT_NAME } else { $env:COMPUTERNAME }),
    [string]$Tags       = $env:PR_AGENT_TAGS,
    [string]$Branch     = $(if ($env:PR_AGENT_BRANCH) { $env:PR_AGENT_BRANCH } else { 'main' })
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw 'install.ps1 must be run from an elevated PowerShell (Run as Administrator).'
}

if (-not $AgentId -or -not $AgentToken) {
    throw 'PR_AGENT_ID and PR_AGENT_TOKEN must be set (env vars or parameters).'
}

# Validate the UUID shape early so a typo doesn't silently land in config.
if ($AgentId -notmatch '^[0-9a-fA-F-]{32,36}$') {
    throw "PR_AGENT_ID does not look like a UUID: $AgentId"
}

$Root      = "$env:ProgramData\PingReportsAgent"
$AgentFile = Join-Path $Root 'agent.ps1'
$ConfFile  = Join-Path $Root 'agent.conf'
$VerFile   = Join-Path $Root 'VERSION'
$LogFile   = Join-Path $Root 'agent.log'
$TaskName  = 'PingReports Agent'
$RepoBase  = "https://raw.githubusercontent.com/PingReports/windows-agent/$Branch"

Write-Host "[+] Installing PingReports Windows agent into $Root"
$null = New-Item -ItemType Directory -Force -Path $Root
$null = New-Item -ItemType Directory -Force -Path (Join-Path $Root 'state')

# Lock down the directory: SYSTEM + Administrators full control, no Users.
try {
    icacls $Root /inheritance:r /grant:r 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' 'BUILTIN\Administrators:(OI)(CI)(F)' /Q | Out-Null
} catch {
    Write-Warning "Could not tighten ACLs on $Root — proceeding with defaults."
}

try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

Write-Host "[+] Downloading agent.ps1 from $RepoBase"
Invoke-WebRequest -Uri "$RepoBase/agent.ps1" -OutFile $AgentFile -UseBasicParsing
Invoke-WebRequest -Uri "$RepoBase/VERSION"   -OutFile $VerFile   -UseBasicParsing

# Random schedule offset 0–299s so 1000 hosts don't all push at :00.
$rand = Get-Random -Minimum 0 -Maximum 300
Write-Host "[+] Schedule jitter: $rand s"

# Write config. Quote values that contain whitespace or `=`.
$confLines = @(
    "# PingReports Windows agent config. Managed by install.ps1.",
    "PR_AGENT_ID=$AgentId",
    "PR_AGENT_TOKEN=$AgentToken",
    "PR_INGEST_URL=$IngestUrl",
    "PR_AGENT_NAME=$AgentName"
)
if ($Tags) { $confLines += "PR_AGENT_TAGS=$Tags" }
$confLines | Set-Content -LiteralPath $ConfFile -Encoding UTF8

# Restrict config file to admins + SYSTEM (it holds the bearer token).
try {
    icacls $ConfFile /inheritance:r /grant:r 'NT AUTHORITY\SYSTEM:(F)' 'BUILTIN\Administrators:(F)' /Q | Out-Null
} catch {}

# Register an Application event log source (best-effort; no-op if exists).
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists('PingReports-Agent')) {
        New-EventLog -LogName Application -Source 'PingReports-Agent' -ErrorAction Stop
    }
} catch {
    Write-Warning "Could not register PingReports-Agent event source: $($_.Exception.Message)"
}

# Schedule the task: every 5 minutes, run as SYSTEM. Use plain schtasks
# instead of the PowerShell scheduling cmdlets so this installer works on
# Windows 10 / Server 2016+ without the ScheduledTasks module quirks.
$psPath = (Get-Command powershell.exe).Source
$execCmd = "`"$psPath`" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AgentFile`""
$execCmdLogged = $execCmd + " *>> `"$LogFile`""

Write-Host "[+] Registering scheduled task '$TaskName'"
schtasks /Delete /TN $TaskName /F 2>$null | Out-Null
# Start time: today's date at a random minute in the next 5 min to seed
# the cadence. /SC MINUTE /MO 5 then drives subsequent firings.
$startMin = (Get-Date).AddSeconds(30 + $rand).ToString('HH:mm')
$null = schtasks /Create `
    /TN $TaskName `
    /TR "$psPath -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AgentFile`"" `
    /SC MINUTE /MO 5 `
    /ST $startMin `
    /RU SYSTEM /RL HIGHEST `
    /F
if ($LASTEXITCODE -ne 0) {
    throw "schtasks /Create failed (exit $LASTEXITCODE)"
}

Write-Host "[+] Triggering first run now to verify connectivity..."
schtasks /Run /TN $TaskName | Out-Null
Start-Sleep -Seconds 6

# Try a synchronous smoke run as well so failures land in the installer's
# console (the scheduled task swallows stdout into the event log).
Write-Host '[+] Smoke run (synchronous):'
& $psPath -NoProfile -ExecutionPolicy Bypass -File $AgentFile

Write-Host ''
Write-Host '----------------------------------------'
Write-Host 'Installed.'
Write-Host "  Task         : $TaskName (every 5 min, runs as SYSTEM)"
Write-Host "  Config       : $ConfFile"
Write-Host "  Agent script : $AgentFile"
Write-Host "  Log          : $LogFile (also Event Viewer → Application → PingReports-Agent)"
Write-Host ''
Write-Host 'To uninstall:'
Write-Host "  irm https://raw.githubusercontent.com/PingReports/windows-agent/$Branch/uninstall.ps1 | iex"
Write-Host '----------------------------------------'
