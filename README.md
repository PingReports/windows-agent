# PingReports Windows agent

Lightweight PowerShell agent for [PingReports](https://app.pingreports.com).
Pushes host metrics, inventory and service state to your workspace every
5 minutes.

## Install (one-liner)

In an **elevated PowerShell**, register the agent in the PingReports UI
(`/agents/new`) to obtain an agent id + token, then:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
$env:PR_AGENT_ID    = '<uuid>'
$env:PR_AGENT_TOKEN = '<token>'
irm https://raw.githubusercontent.com/PingReports/windows-agent/main/install.ps1 | iex
```

The installer drops `agent.ps1` into `%ProgramData%\PingReportsAgent\`,
writes `agent.conf` with the token (locked to SYSTEM + Administrators),
registers a Scheduled Task that runs every 5 minutes as `NT AUTHORITY\SYSTEM`,
and fires one immediate push so any auth/connectivity error is visible
in the installer output.

### Optional env

| Variable | Default | Notes |
| --- | --- | --- |
| `PR_AGENT_NAME` | `$env:COMPUTERNAME` | Display name in the UI |
| `PR_AGENT_TAGS` | _(empty)_ | Comma-separated tags |
| `PR_INGEST_URL` | `https://agents.pingreports.com/v1/ingest` | Override for self-hosted |
| `PR_AGENT_BRANCH` | `main` | Pin installer to a release branch |

## Uninstall

```powershell
irm https://raw.githubusercontent.com/PingReports/windows-agent/main/uninstall.ps1 | iex
```

Removes the scheduled task and `%ProgramData%\PingReportsAgent\`.

## What it collects

- **CPU / memory** — `cpu_busy_pct`, `cpu_user_pct`, `mem_total_kb`, `mem_used_pct`, etc.
- **Disk** — per-volume size / used / available / used_pct.
- **Disk I/O** — per-physical-disk read/write bytes/s, busy %.
- **Network** — per-NIC rx/tx bytes, packets, errors.
- **Sockets** — TCP by state, UDP total.
- **Services** — counts + per-service inventory (state, display name, failed-auto-start).
- **Processes** — top-N by CPU + RSS, with per-process metric drill-down.
- **System info** — vendor, board, BIOS, OS build, DNS resolvers, CPU model.
- **GPUs** — name, driver, vendor (NVIDIA / AMD / Intel).
- **Hyper-V VMs** — name, state, vCPUs, memory (when the Hyper-V role is installed).
- **Docker Desktop** — version + container list (when `docker` is on PATH).
- **Windows updates** — reboot-required flag.

Wire format matches the [linux-agent](https://github.com/PingReports/linux-agent)
so the same dashboards and alert presets apply to mixed Linux + Windows
fleets.

## Local testing

```powershell
# Run one push synchronously (uses %ProgramData%\PingReportsAgent\agent.conf):
powershell -ExecutionPolicy Bypass -File C:\ProgramData\PingReportsAgent\agent.ps1

# Tail the log:
Get-Content C:\ProgramData\PingReportsAgent\agent.log -Wait

# Event Viewer → Windows Logs → Application → Source: PingReports-Agent
```
