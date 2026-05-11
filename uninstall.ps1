#requires -version 5.1
<#
Removes the PingReports Windows agent: kills the Scheduled Task and
deletes %ProgramData%\PingReportsAgent\ in full.

Usage (elevated PowerShell):
  irm https://raw.githubusercontent.com/PingReports/windows-agent/main/uninstall.ps1 | iex
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw 'uninstall.ps1 must be run from an elevated PowerShell.'
}

$Root     = "$env:ProgramData\PingReportsAgent"
$TaskName = 'PingReports Agent'

Write-Host "[+] Removing scheduled task '$TaskName'"
schtasks /Delete /TN $TaskName /F 2>$null | Out-Null

if (Test-Path $Root) {
    Write-Host "[+] Deleting $Root"
    Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
}

try {
    if ([System.Diagnostics.EventLog]::SourceExists('PingReports-Agent')) {
        Remove-EventLog -Source 'PingReports-Agent' -ErrorAction Stop
        Write-Host '[+] Removed Application event log source PingReports-Agent.'
    }
} catch {
    Write-Warning "Could not remove event log source: $($_.Exception.Message)"
}

Write-Host 'Uninstalled.'
