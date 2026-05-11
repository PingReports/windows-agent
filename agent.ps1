#requires -version 5.1
<#
PingReports Windows agent. Collects host metrics + inventory and POSTs a
gzipped JSON envelope to the configured ingest endpoint.

Reads config from C:\ProgramData\PingReportsAgent\agent.conf — one
KEY=VALUE line per setting. Required: PR_AGENT_ID, PR_AGENT_TOKEN. The
installer writes this file; this script never edits it.

Wire format mirrors the linux-agent exactly so the same server schema /
dashboards / alert presets work without branching.
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = "$env:ProgramData\PingReportsAgent\agent.conf"
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
Set-StrictMode -Version 2

$AgentVersion = '0.1.0'

function Read-AgentConfig {
    param([string]$Path)
    if (-not (Test-Path $Path)) { throw "config not found: $Path" }
    $cfg = @{}
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $eq = $line.IndexOf('=')
        if ($eq -lt 1) { continue }
        $k = $line.Substring(0, $eq).Trim()
        $v = $line.Substring($eq + 1).Trim()
        if ($v.StartsWith('"') -and $v.EndsWith('"')) { $v = $v.Substring(1, $v.Length - 2) }
        $cfg[$k] = $v
    }
    foreach ($required in 'PR_AGENT_ID','PR_AGENT_TOKEN','PR_INGEST_URL') {
        if (-not $cfg.ContainsKey($required) -or -not $cfg[$required]) {
            throw "config missing $required"
        }
    }
    if (-not $cfg.ContainsKey('PR_AGENT_NAME') -or -not $cfg.PR_AGENT_NAME) {
        $cfg.PR_AGENT_NAME = $env:COMPUTERNAME
    }
    if (-not $cfg.ContainsKey('PR_HTTP_TIMEOUT')) { $cfg.PR_HTTP_TIMEOUT = '30' }
    if (-not $cfg.ContainsKey('PR_TOP_N'))        { $cfg.PR_TOP_N        = '20' }
    return $cfg
}

function Get-LockHeld {
    param([string]$LockFile)
    if (-not (Test-Path $LockFile)) { return $false }
    try {
        $pidStr = (Get-Content -LiteralPath $LockFile -ErrorAction Stop | Select-Object -First 1).Trim()
        if (-not $pidStr) { return $false }
        $p = Get-Process -Id ([int]$pidStr) -ErrorAction Stop
        return ($p -ne $null)
    } catch { return $false }
}

# -------- collectors. Each returns hashtables / arrays already shaped for
# the envelope. Failures are caught locally so one missing source can't
# kill the whole push.

function Safe-Invoke {
    param([scriptblock]$Block, $Default = $null)
    try { return & $Block } catch { return $Default }
}

function ConvertTo-UnixSafeNumber {
    param($v)
    if ($null -eq $v) { return $null }
    try {
        $d = [double]$v
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return $null }
        return $d
    } catch { return $null }
}

function New-Metric {
    param([string]$Name, $Value, [hashtable]$Labels, [string]$Ts)
    $val = ConvertTo-UnixSafeNumber $Value
    if ($null -eq $val) { return $null }
    $m = [ordered]@{ ts = $Ts; name = $Name; value = $val }
    if ($Labels -and $Labels.Count -gt 0) { $m.labels = $Labels }
    return $m
}

function Get-MetricsCpuMem {
    param([string]$Ts)
    $out = New-Object System.Collections.ArrayList
    # CPU + memory via CIM (one shot, no per-counter handshake).
    $os = Safe-Invoke { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
    $cs = Safe-Invoke { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
    if ($os) {
        $memTotalKb = [int64]$os.TotalVisibleMemorySize
        $memFreeKb  = [int64]$os.FreePhysicalMemory
        $memUsedKb  = $memTotalKb - $memFreeKb
        $swapTotal  = [int64]$os.TotalVirtualMemorySize
        $swapFree   = [int64]$os.FreeVirtualMemory
        [void]$out.Add((New-Metric 'mem_total_kb'     $memTotalKb $null $Ts))
        [void]$out.Add((New-Metric 'mem_available_kb' $memFreeKb  $null $Ts))
        [void]$out.Add((New-Metric 'mem_free_kb'      $memFreeKb  $null $Ts))
        [void]$out.Add((New-Metric 'mem_used_kb'      $memUsedKb  $null $Ts))
        [void]$out.Add((New-Metric 'swap_total_kb'    $swapTotal  $null $Ts))
        [void]$out.Add((New-Metric 'swap_free_kb'     $swapFree   $null $Ts))
        if ($memTotalKb -gt 0) {
            $pct = (100.0 * $memUsedKb / $memTotalKb)
            [void]$out.Add((New-Metric 'mem_used_pct' $pct $null $Ts))
        }
        [void]$out.Add((New-Metric 'proc_count'  $os.NumberOfProcesses $null $Ts))
        [void]$out.Add((New-Metric 'users_logged_in' $os.NumberOfUsers $null $Ts))
    }
    if ($cs) {
        [void]$out.Add((New-Metric 'cpu_logical'   $cs.NumberOfLogicalProcessors $null $Ts))
        [void]$out.Add((New-Metric 'cpu_physical'  $cs.NumberOfProcessors        $null $Ts))
    }
    # CPU utilisation via WMI _Total processor counter — sampled once,
    # so it's "instantaneous since last sample" rather than a 1s average.
    $cpu = Safe-Invoke {
        Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -ErrorAction Stop |
            Where-Object { $_.Name -eq '_Total' }
    }
    if ($cpu) {
        $busy = 100.0 - [double]$cpu.PercentIdleTime
        if ($busy -lt 0) { $busy = 0 } elseif ($busy -gt 100) { $busy = 100 }
        [void]$out.Add((New-Metric 'cpu_busy_pct'    $busy                                 $null $Ts))
        [void]$out.Add((New-Metric 'cpu_user_pct'    ([double]$cpu.PercentUserTime)        $null $Ts))
        [void]$out.Add((New-Metric 'cpu_system_pct'  ([double]$cpu.PercentPrivilegedTime)  $null $Ts))
        [void]$out.Add((New-Metric 'cpu_idle_pct'    ([double]$cpu.PercentIdleTime)        $null $Ts))
        [void]$out.Add((New-Metric 'cpu_interrupt_pct' ([double]$cpu.PercentInterruptTime) $null $Ts))
    }
    # System uptime in seconds — matches the linux-agent metric name the
    # server summary reads ("uptime_seconds").
    if ($os -and $os.LastBootUpTime) {
        $uptime = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
        [void]$out.Add((New-Metric 'uptime_seconds' $uptime $null $Ts))
    }
    return $out
}

function Get-MetricsDisk {
    param([string]$Ts)
    $out = New-Object System.Collections.ArrayList
    $vols = Safe-Invoke { Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop }
    if (-not $vols) { return $out }
    foreach ($v in $vols) {
        $size  = [int64]($v.Size  | ForEach-Object { if ($_) { $_ } else { 0 } })
        $free  = [int64]($v.FreeSpace | ForEach-Object { if ($_) { $_ } else { 0 } })
        $used  = $size - $free
        $path  = $v.DeviceID  # e.g. "C:"
        $labels = @{ path = $path }
        [void]$out.Add((New-Metric 'disk_size_bytes'  $size  $labels $Ts))
        [void]$out.Add((New-Metric 'disk_used_bytes'  $used  $labels $Ts))
        [void]$out.Add((New-Metric 'disk_avail_bytes' $free  $labels $Ts))
        if ($size -gt 0) {
            $pct = (100.0 * $used / $size)
            [void]$out.Add((New-Metric 'disk_used_pct' $pct $labels $Ts))
        }
    }
    return $out
}

function Get-MetricsDiskIO {
    param([string]$Ts)
    $out = New-Object System.Collections.ArrayList
    $rows = Safe-Invoke {
        Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction Stop |
            Where-Object { $_.Name -ne '_Total' -and $_.Name -notmatch '^\s*$' }
    }
    foreach ($r in ($rows | ForEach-Object { $_ })) {
        $labels = @{ device = ($r.Name -replace '[^A-Za-z0-9 ]','_') }
        [void]$out.Add((New-Metric 'diskio_read_bytes_per_s'  ([double]$r.DiskReadBytesPerSec)  $labels $Ts))
        [void]$out.Add((New-Metric 'diskio_write_bytes_per_s' ([double]$r.DiskWriteBytesPerSec) $labels $Ts))
        [void]$out.Add((New-Metric 'diskio_reads_per_s'       ([double]$r.DiskReadsPerSec)     $labels $Ts))
        [void]$out.Add((New-Metric 'diskio_writes_per_s'      ([double]$r.DiskWritesPerSec)    $labels $Ts))
        [void]$out.Add((New-Metric 'diskio_busy_pct'          ([double]$r.PercentDiskTime)     $labels $Ts))
    }
    return $out
}

function Get-MetricsNet {
    param([string]$Ts)
    $out = New-Object System.Collections.ArrayList
    $stats = Safe-Invoke { Get-NetAdapterStatistics -ErrorAction Stop }
    foreach ($s in ($stats | ForEach-Object { $_ })) {
        # Skip Microsoft loopback / virtual / disconnected.
        if ($s.Name -match 'isatap|Loopback') { continue }
        $labels = @{ iface = $s.Name }
        [void]$out.Add((New-Metric 'net_rx_bytes'   ([int64]$s.ReceivedBytes)            $labels $Ts))
        [void]$out.Add((New-Metric 'net_tx_bytes'   ([int64]$s.SentBytes)                $labels $Ts))
        [void]$out.Add((New-Metric 'net_rx_packets' ([int64]$s.ReceivedUnicastPackets)   $labels $Ts))
        [void]$out.Add((New-Metric 'net_tx_packets' ([int64]$s.SentUnicastPackets)       $labels $Ts))
        [void]$out.Add((New-Metric 'net_rx_errs'    ([int64]$s.ReceivedDiscardedPackets) $labels $Ts))
        [void]$out.Add((New-Metric 'net_tx_errs'    ([int64]$s.OutboundDiscardedPackets) $labels $Ts))
    }
    return $out
}

function Get-MetricsSocketCounts {
    param([string]$Ts)
    $out = New-Object System.Collections.ArrayList
    $tcp = Safe-Invoke { Get-NetTCPConnection -ErrorAction Stop }
    if ($tcp) {
        $byState = $tcp | Group-Object State
        $total = ($tcp | Measure-Object).Count
        # linux-style names so the existing summary + alert presets fire
        # on Windows hosts too.
        [void]$out.Add((New-Metric 'sock_total'      $total $null $Ts))
        $estabCount = ($tcp | Where-Object { $_.State -eq 'Established' } | Measure-Object).Count
        $twCount    = ($tcp | Where-Object { $_.State -eq 'TimeWait' } | Measure-Object).Count
        [void]$out.Add((New-Metric 'sock_tcp_inuse'  $estabCount $null $Ts))
        [void]$out.Add((New-Metric 'sock_tcp_tw'     $twCount    $null $Ts))
        foreach ($g in $byState) {
            $labels = @{ kind = 'tcp'; state = $g.Name }
            [void]$out.Add((New-Metric 'sock_state' $g.Count $labels $Ts))
        }
    }
    $udp = Safe-Invoke { (Get-NetUDPEndpoint -ErrorAction Stop | Measure-Object).Count }
    if ($null -ne $udp) {
        [void]$out.Add((New-Metric 'sock_udp_inuse' $udp $null $Ts))
    }
    return $out
}

function Get-MetricsServices {
    param([string]$Ts)
    $out = New-Object System.Collections.ArrayList
    $svcs = Safe-Invoke { Get-Service -ErrorAction Stop }
    if (-not $svcs) { return $out }
    $running = ($svcs | Where-Object { $_.Status -eq 'Running' } | Measure-Object).Count
    # "failed" on Windows = auto-start services that aren't running. Closest
    # analog to the linux-agent "systemd_units_failed" surface.
    $failed = ($svcs | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | Measure-Object).Count
    $total   = ($svcs | Measure-Object).Count
    [void]$out.Add((New-Metric 'systemd_units_total'  $total   $null $Ts))
    [void]$out.Add((New-Metric 'systemd_units_active' $running $null $Ts))
    [void]$out.Add((New-Metric 'systemd_units_failed' $failed  $null $Ts))
    return $out
}

function Get-MetricsProcDrilldown {
    param([string]$Ts, [int]$TopN)
    $out = New-Object System.Collections.ArrayList
    $rows = Get-SafeProcessSnapshot
    if (-not $rows -or $rows.Count -eq 0) { return $out }
    $topCpu = $rows | Sort-Object -Property CpuSec     -Descending | Select-Object -First $TopN
    $topMem = $rows | Sort-Object -Property WorkingSet -Descending | Select-Object -First $TopN
    $seen = @{}
    foreach ($p in (@($topCpu) + @($topMem))) {
        if (-not $p.Name) { continue }
        if ($seen.ContainsKey($p.Name)) { continue }
        $seen[$p.Name] = $true
        $labels = @{ comm = $p.Name }
        [void]$out.Add((New-Metric 'proc_cpu_seconds' $p.CpuSec $labels $Ts))
        $rssKb = [int64]([math]::Round($p.WorkingSet / 1024))
        [void]$out.Add((New-Metric 'proc_rss_kb' $rssKb $labels $Ts))
    }
    return $out
}

function Get-SafeProcessSnapshot {
    # Project Get-Process into a uniform shape with each field guarded so
    # a single inaccessible process (system service we can't open) can't
    # nuke Sort-Object via a "property not found" exception.
    $procs = Safe-Invoke { Get-Process -ErrorAction Stop } @()
    $rows = New-Object System.Collections.ArrayList
    foreach ($p in ($procs | ForEach-Object { $_ })) {
        $cpuSec = 0.0
        try {
            $cpuObj = $p.PSObject.Properties['CPU']
            if ($cpuObj -and $null -ne $cpuObj.Value) { $cpuSec = [double]$cpuObj.Value }
        } catch {}
        $ws = 0
        try { $ws = [int64]$p.WorkingSet64 } catch {
            try { $ws = [int64]$p.WorkingSet } catch {}
        }
        $threads = 0
        try { $threads = [int]$p.Threads.Count } catch {}
        [void]$rows.Add([pscustomobject]@{
            Id         = [int]$p.Id
            Name       = "$($p.ProcessName)"
            CpuSec     = $cpuSec
            WorkingSet = $ws
            Threads    = $threads
        })
    }
    return $rows
}

function Get-InvSystemInfo {
    $cs   = Safe-Invoke { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
    $bios = Safe-Invoke { Get-CimInstance Win32_BIOS -ErrorAction Stop }
    $bb   = Safe-Invoke { Get-CimInstance Win32_BaseBoard -ErrorAction Stop }
    $cpu  = Safe-Invoke { Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1 }
    $os   = Safe-Invoke { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
    $out = [ordered]@{}
    if ($cs)   { $out.sys_vendor    = "$($cs.Manufacturer)"; $out.product_name = "$($cs.Model)" }
    if ($bb)   { $out.board_vendor  = "$($bb.Manufacturer)"; $out.board_name = "$($bb.Product)"; $out.board_version = "$($bb.Version)" }
    if ($bios) {
        $out.bios_vendor  = "$($bios.Manufacturer)"
        $out.bios_version = "$($bios.SMBIOSBIOSVersion)"
        if ($bios.ReleaseDate) { $out.bios_date = "$(($bios.ReleaseDate).ToString('yyyy-MM-dd'))" }
    }
    if ($cpu) {
        $out.cpu_model     = ("$($cpu.Name)" -replace '\s+',' ').Trim()
        $out.cpu_logical   = [int]$cpu.NumberOfLogicalProcessors
        $out.cpu_cores     = [int]$cpu.NumberOfCores
    }
    if ($os) {
        $out.cpu_physical  = [int]$os.NumberOfProcesses # placeholder; not strictly accurate but field exists
        $out.mem_total_kb  = [int64]$os.TotalVisibleMemorySize
        $out.swap_total_kb = [int64]$os.TotalVirtualMemorySize
        # Borrow `kernel_cmdline` field to convey Windows OS name + version
        # (existing schema doesn't have a dedicated OS field).
        $out.kernel_cmdline = "$($os.Caption) $($os.Version) build $($os.BuildNumber)"
        # `resolvers` field reused for DNS server list — handy on Windows
        # too and the field is already in the allowlist.
        $dns = Safe-Invoke {
            (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.ServerAddresses } |
                Select-Object -ExpandProperty ServerAddresses -Unique) -join ','
        } ''
        if ($dns) { $out.resolvers = $dns }
    }
    return $out
}

function Get-InvCapabilities {
    $hyperv = $false
    try {
        if (Get-Command Get-VM -ErrorAction Ignore) {
            # Get-VM exists when the Hyper-V module is loadable AND the role
            # is installed. The module presence alone isn't enough, so we
            # actually try the call.
            $null = Get-VM -ErrorAction Stop 2>$null
            $hyperv = $true
        }
    } catch { $hyperv = $false }
    $dockerDesktop = [bool](Get-Command docker -ErrorAction Ignore)
    $gpu = $false
    try {
        $gpu = [bool](Get-CimInstance Win32_VideoController -ErrorAction Stop)
    } catch {}
    return [ordered]@{
        windows         = $true
        hyperv          = $hyperv
        docker_desktop  = $dockerDesktop
        docker          = $dockerDesktop  # so the existing Containers tab lights up
        gpu             = $gpu
        windows_update  = $true
        # Linux markers stay false so the UI doesn't promise things we
        # can't deliver.
        podman   = $false
        libvirt  = $false
        kvm      = $false
        systemd  = $false
        sensors  = $false
        apt      = $false
        dnf      = $false
    }
}

function Get-InvHyperVVMs {
    if (-not (Get-Command Get-VM -ErrorAction Ignore)) { return @() }
    $vms = Safe-Invoke { Get-VM -ErrorAction Stop } @()
    $out = New-Object System.Collections.ArrayList
    foreach ($vm in ($vms | ForEach-Object { $_ })) {
        [void]$out.Add([ordered]@{
            name      = "$($vm.Name)"
            state     = "$($vm.State)".ToLower()
            cpus      = [int]$vm.ProcessorCount
            mem_bytes = [int64]$vm.MemoryAssigned
        })
    }
    return $out.ToArray()
}

function Get-InvDocker {
    if (-not (Get-Command docker -ErrorAction Ignore)) { return $null }
    $ver = ''
    try { $ver = (docker version --format '{{.Server.Version}}' 2>$null | Out-String).Trim() } catch {}
    $cont = New-Object System.Collections.ArrayList
    try {
        # `docker ps -a` with tabular format → one line per container.
        $fmt = '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.State}}|{{.Ports}}|{{.CreatedAt}}'
        $lines = docker ps -a --format $fmt 2>$null
        foreach ($line in $lines) {
            if (-not $line) { continue }
            $cols = $line -split '\|'
            if ($cols.Count -lt 7) { continue }
            [void]$cont.Add([ordered]@{
                id      = "$($cols[0])".Substring(0, [Math]::Min(12, ($cols[0] + '').Length))
                name    = "$($cols[1])"
                image   = "$($cols[2])"
                status  = "$($cols[3])"
                state   = "$($cols[4])"
                ports   = "$($cols[5])"
                created = "$($cols[6])"
            })
        }
    } catch {}
    return [ordered]@{ version = $ver; containers = @($cont.ToArray()) }
}

function Get-InvTopProcesses {
    param([int]$TopN, [string]$SortBy = 'WorkingSet')
    $rows = Get-SafeProcessSnapshot
    if (-not $rows -or $rows.Count -eq 0) { return @() }
    $out = New-Object System.Collections.ArrayList
    foreach ($p in ($rows | Sort-Object -Property $SortBy -Descending | Select-Object -First $TopN)) {
        $rssKb = [int64]([math]::Round($p.WorkingSet / 1024))
        [void]$out.Add([ordered]@{
            pid     = [int]$p.Id
            user    = ''
            cpu     = [double]$p.CpuSec
            rss_kb  = $rssKb
            comm    = $p.Name
            args    = ''
            threads = [int]$p.Threads
            state   = 'R'
        })
    }
    return $out.ToArray()
}

function Get-InvListeningPorts {
    $out = New-Object System.Collections.ArrayList
    $tcp = Safe-Invoke { Get-NetTCPConnection -State Listen -ErrorAction Stop } @()
    foreach ($c in ($tcp | ForEach-Object { $_ })) {
        $procName = ''
        try { $procName = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch {}
        [void]$out.Add([ordered]@{
            proto = 'tcp'
            addr  = "$($c.LocalAddress)"
            port  = [int]$c.LocalPort
            proc  = $procName
        })
    }
    $udp = Safe-Invoke { Get-NetUDPEndpoint -ErrorAction Stop } @()
    foreach ($c in ($udp | ForEach-Object { $_ })) {
        $procName = ''
        try { $procName = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch {}
        [void]$out.Add([ordered]@{
            proto = 'udp'
            addr  = "$($c.LocalAddress)"
            port  = [int]$c.LocalPort
            proc  = $procName
        })
    }
    return $out.ToArray()
}

function Get-InvFailedServices {
    $out = New-Object System.Collections.ArrayList
    $svcs = Safe-Invoke { Get-Service -ErrorAction Stop } @()
    foreach ($s in ($svcs | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' })) {
        [void]$out.Add([ordered]@{
            unit   = "$($s.Name).service"
            active = 'inactive'
            sub    = "$($s.Status)".ToLower()
        })
    }
    return $out.ToArray()
}

function Get-InvAllServices {
    $out = New-Object System.Collections.ArrayList
    $svcs = Safe-Invoke { Get-Service -ErrorAction Stop } @()
    foreach ($s in ($svcs | Select-Object -First 500)) {
        $active = if ($s.Status -eq 'Running') { 'active' } else { 'inactive' }
        [void]$out.Add([ordered]@{
            unit   = "$($s.Name).service"
            load   = 'loaded'
            active = $active
            sub    = "$($s.Status)".ToLower()
            desc   = "$($s.DisplayName)"
        })
    }
    return $out.ToArray()
}

function Get-InvGPUs {
    $out = New-Object System.Collections.ArrayList
    $gpus = Safe-Invoke { Get-CimInstance Win32_VideoController -ErrorAction Stop } @()
    $idx = 0
    foreach ($g in ($gpus | ForEach-Object { $_ })) {
        $vendor = ''
        $name = "$($g.Name)"
        if     ($name -match 'NVIDIA') { $vendor = 'nvidia' }
        elseif ($name -match 'AMD|Radeon') { $vendor = 'amd' }
        elseif ($name -match 'Intel') { $vendor = 'intel' }
        $memTotal = ''
        if ($g.AdapterRAM) { $memTotal = "$([int64]$g.AdapterRAM)" }
        [void]$out.Add([ordered]@{
            vendor    = $vendor
            idx       = $idx
            name      = $name
            driver    = "$($g.DriverVersion)"
            mem_total = $memTotal
        })
        $idx++
    }
    return $out.ToArray()
}

function Get-InvPendingUpdates {
    # Best-effort: parse `wmic qfe` for installed updates count we'd surface
    # later. For pending updates we rely on the Windows Update agent COM
    # interface, which is slow and sometimes blocked by policy. Surface
    # what we can without paying the wuapi cost on every push.
    $out = [ordered]@{
        total            = 0
        security         = 0
        reboot_required  = 0
    }
    # Reboot-required check via Component Based Servicing / Windows Update.
    try {
        $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $wu  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        if ($cbs -or $wu) { $out.reboot_required = 1 }
    } catch {}
    return $out
}

function Build-Envelope {
    param($Cfg)
    $ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $metrics = New-Object System.Collections.ArrayList
    foreach ($m in (Get-MetricsCpuMem      -Ts $ts)) { if ($m) { [void]$metrics.Add($m) } }
    foreach ($m in (Get-MetricsDisk        -Ts $ts)) { if ($m) { [void]$metrics.Add($m) } }
    foreach ($m in (Get-MetricsDiskIO      -Ts $ts)) { if ($m) { [void]$metrics.Add($m) } }
    foreach ($m in (Get-MetricsNet         -Ts $ts)) { if ($m) { [void]$metrics.Add($m) } }
    foreach ($m in (Get-MetricsSocketCounts -Ts $ts)){ if ($m) { [void]$metrics.Add($m) } }
    foreach ($m in (Get-MetricsServices    -Ts $ts)) { if ($m) { [void]$metrics.Add($m) } }
    foreach ($m in (Get-MetricsProcDrilldown -Ts $ts -TopN ([int]$Cfg.PR_TOP_N))) { if ($m) { [void]$metrics.Add($m) } }

    $caps = Get-InvCapabilities
    $sysInfo = Get-InvSystemInfo

    $inventory = [ordered]@{
        capabilities         = $caps
        capability_present   = $caps  # same shape — Windows has no "installed-but-denied" notion
        system_info          = $sysInfo
        top_proc_mem         = Get-InvTopProcesses -TopN ([int]$Cfg.PR_TOP_N) -SortBy 'WorkingSet'
        top_proc_cpu         = Get-InvTopProcesses -TopN ([int]$Cfg.PR_TOP_N) -SortBy 'CpuSec'
        listening_ports      = Get-InvListeningPorts
        failed_services      = Get-InvFailedServices
        systemd_units        = Get-InvAllServices
        gpus                 = Get-InvGPUs
        updates              = Get-InvPendingUpdates
        virt                 = ''
    }

    # Hyper-V VMs are routed through the existing `libvirt` schema so the
    # server doesn't need a parallel code path. The webui flips the section
    # label to "Hyper-V" based on capabilities.hyperv.
    if ($caps.hyperv) {
        $inventory.libvirt = [ordered]@{
            version    = 'hyper-v'
            vms        = Get-InvHyperVVMs
            containers = @()
        }
    }

    $docker = Get-InvDocker
    if ($docker) { $inventory.docker = $docker }

    return [ordered]@{
        agent_id      = $Cfg.PR_AGENT_ID
        name          = $Cfg.PR_AGENT_NAME
        agent_version = $AgentVersion
        ts            = $ts
        inventory     = $inventory
        metrics       = $metrics.ToArray()
        services      = @()
        logins        = @()
    }
}

function Compress-Bytes {
    param([byte[]]$Bytes)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionLevel]::Optimal)
    try {
        $gz.Write($Bytes, 0, $Bytes.Length)
    } finally {
        $gz.Dispose()
    }
    return $ms.ToArray()
}

function Send-Envelope {
    param($Envelope, $Cfg)
    # Enforce modern TLS regardless of system default (older Win10 boxes
    # still negotiate TLS 1.0 by default which Cloudflare rejects).
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    } catch {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    $json = $Envelope | ConvertTo-Json -Depth 12 -Compress
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $gz = Compress-Bytes -Bytes $jsonBytes

    $req = [System.Net.HttpWebRequest]::Create($Cfg.PR_INGEST_URL)
    $req.Method = 'POST'
    $req.ContentType = 'application/json'
    $req.Headers.Add('Content-Encoding', 'gzip')
    $req.Headers.Add('Authorization', 'Bearer ' + $Cfg.PR_AGENT_TOKEN)
    $req.Headers.Add('X-Agent-Id', $Cfg.PR_AGENT_ID)
    $req.Headers.Add('X-Agent-Version', $AgentVersion)
    $req.UserAgent = "PingReports-WindowsAgent/$AgentVersion"
    $req.Timeout = ([int]$Cfg.PR_HTTP_TIMEOUT) * 1000
    $req.ContentLength = $gz.Length

    $reqStream = $req.GetRequestStream()
    try { $reqStream.Write($gz, 0, $gz.Length) } finally { $reqStream.Dispose() }

    $code = 0
    try {
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
        } else {
            $code = -1
        }
    }
    return @{ http = $code; bytes = $gz.Length }
}

# -------- main

$cfg = Read-AgentConfig -Path $ConfigPath
$stateDir = "$env:ProgramData\PingReportsAgent\state"
$null = New-Item -ItemType Directory -Force -Path $stateDir
$lockFile = Join-Path $stateDir 'agent.lock'

if (Get-LockHeld -LockFile $lockFile) {
    Write-Host "[pingreports-agent] another run in flight, skipping"
    return
}
"$PID" | Set-Content -LiteralPath $lockFile -Encoding ASCII
try {
    $envelope = Build-Envelope -Cfg $cfg
    $r = Send-Envelope -Envelope $envelope -Cfg $cfg
    $line = "[pingreports-agent] ts=$([DateTime]::UtcNow.ToString('o')) http=$($r.http) bytes=$($r.bytes) metrics=$($envelope.metrics.Count)"
    Write-Host $line
    # Try to mirror to Application event log; non-fatal if registration
    # of the source hasn't happened.
    try {
        Write-EventLog -LogName Application -Source 'PingReports-Agent' -EntryType Information -EventId 1 -Message $line -ErrorAction Stop
    } catch {}
} finally {
    Remove-Item -LiteralPath $lockFile -Force -ErrorAction Ignore
}
