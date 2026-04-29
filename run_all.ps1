param(
    [switch]$DemoBurst
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$streamlitExe = Join-Path $root ".venv\Scripts\streamlit.exe"
$logsDir = Join-Path $root "agentshield\logs"
$eventLogPath = Join-Path $logsDir "agentshield.jsonl"

if (-not (Test-Path $streamlitExe)) {
    throw "Missing Streamlit executable: $streamlitExe"
}

New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

$logNames = @(
    "Microsoft-Windows-NCSI/Operational",
    "Microsoft-Windows-NetworkProfile/Operational",
    "Microsoft-Windows-WinINet/Operational",
    "Microsoft-Windows-WLAN-AutoConfig/Operational",
    "Microsoft-Windows-WFP/Operational"
)

Write-Host "Starting Windows ETW collector (NCSI/NetworkProfile/WinINet/WLAN/WFP) -> agentshield/logs/agentshield.jsonl"
$collectorJob = Start-Job -ScriptBlock {
    param($outputPath, $selectedLogs)

    $ErrorActionPreference = "SilentlyContinue"
    $lastByLog = @{}

    foreach ($logName in $selectedLogs) {
        $lastByLog[$logName] = 0L
        try {
            $latest = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction Stop
            if ($latest) {
                $seed = [int64]$latest.RecordId - 150
                if ($seed -lt 0) {
                    $seed = 0
                }
                $lastByLog[$logName] = $seed
            }
        } catch {
            # Log may be unavailable without elevation; skip dynamically in main loop.
        }
    }

    while ($true) {
        foreach ($logName in $selectedLogs) {
            try {
                $events = Get-WinEvent -LogName $logName -MaxEvents 150 | Sort-Object RecordId
                foreach ($evt in $events) {
                    $rid = [int64]$evt.RecordId
                    if ($rid -le [int64]$lastByLog[$logName]) {
                        continue
                    }
                    $lastByLog[$logName] = $rid

                    $procId = 0
                    if ($evt.Message -match "Owning Process ID:\s*(\d+)") {
                        $procId = [int]$Matches[1]
                    } elseif ($evt.Message -match "Process\s*ID\s*[:=]\s*(\d+)") {
                        $procId = [int]$Matches[1]
                    }

                    $procName = "unknown"
                    if ($procId -gt 0) {
                        try {
                            $procName = (Get-Process -Id $procId -ErrorAction Stop).ProcessName
                        } catch {
                            $procName = "unknown"
                        }
                    }

                    $tsNs = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1000000)
                    $payload = [ordered]@{
                        timestamp_ns = $tsNs
                        pid = $procId
                        uid = 0
                        ppid = 0
                        event_type = "etw_event_$($evt.Id)"
                        process_name = $procName
                        destination_ip = "0.0.0.0"
                        destination_port = 0
                        size = 0
                        ip_version = 4
                        source = "etw"
                        cmdline = "ETW:$logName"
                        lineage = @("windows", "etw")
                        dns_name = ""
                        env = @{}
                    }

                    ($payload | ConvertTo-Json -Compress) | Add-Content -Path $outputPath -Encoding utf8
                }
            } catch {
                # Keep collector alive across transient ETW read/access failures.
            }
        }

        Start-Sleep -Seconds 2
    }
} -ArgumentList $eventLogPath, $logNames

Write-Host "ETW collector job started with Id=$($collectorJob.Id)"

Write-Host "Starting native TCP sampler (Get-NetTCPConnection) -> agentshield/logs/agentshield.jsonl"
$tcpSamplerJob = Start-Job -ScriptBlock {
    param($outputPath)

    $ErrorActionPreference = "SilentlyContinue"
    $seen = @{}

    while ($true) {
        try {
            $rows = Get-NetTCPConnection | Where-Object { $_.State -in @("Established", "SynSent", "SynReceived", "TimeWait") }
            foreach ($row in $rows) {
                $key = "{0}:{1}->{2}:{3}:{4}" -f $row.OwningProcess, $row.LocalAddress, $row.LocalPort, $row.RemoteAddress, $row.RemotePort
                if ($seen.ContainsKey($key)) {
                    continue
                }
                $seen[$key] = $true

                $procName = "unknown"
                try {
                    $procName = (Get-Process -Id $row.OwningProcess -ErrorAction Stop).ProcessName
                } catch {
                    $procName = "unknown"
                }

                $tsNs = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1000000)
                $payload = [ordered]@{
                    timestamp_ns = $tsNs
                    pid = [int]$row.OwningProcess
                    uid = 0
                    ppid = 0
                    event_type = "tcp_connection"
                    process_name = $procName
                    destination_ip = [string]$row.RemoteAddress
                    destination_port = [int]$row.RemotePort
                    size = 0
                    ip_version = 4
                    source = "windows_tcp"
                    cmdline = "NETTCP:$($row.State)"
                    lineage = @("windows", "net")
                    dns_name = ""
                    env = @{}
                }

                ($payload | ConvertTo-Json -Compress) | Add-Content -Path $outputPath -Encoding utf8
            }
        } catch {
            # Keep sampler alive if transient command failures occur.
        }

        Start-Sleep -Seconds 2
    }
} -ArgumentList $eventLogPath

Write-Host "TCP sampler job started with Id=$($tcpSamplerJob.Id)"

if ($DemoBurst) {
    Write-Host "Starting local demo burst (safe log-only anomaly simulation) -> agentshield/logs/{agentshield,incidents}.jsonl"
    $demoBurstJob = Start-Job -ScriptBlock {
        param($eventPath, $incidentPath)

        $ErrorActionPreference = "SilentlyContinue"
        $procName = "loadtest"
        $pid = 4242

        for ($i = 0; $i -lt 16; $i++) {
            $tsUtc = [DateTimeOffset]::UtcNow
            $tsNs = [int64]($tsUtc.ToUnixTimeMilliseconds() * 1000000)
            $destinationPort = if ($i % 3 -eq 0) { 80 } elseif ($i % 3 -eq 1) { 443 } else { 4444 }
            $action = if ($i % 4 -eq 0) { "kill" } else { "alert" }
            $eventPayload = [ordered]@{
                timestamp_ns = $tsNs
                pid = $pid
                uid = 1000
                ppid = 1
                event_type = "demo_dos_burst"
                process_name = $procName
                destination_ip = "127.0.0.1"
                destination_port = $destinationPort
                size = 4096 + ($i * 128)
                ip_version = 4
                source = "demo_dos"
                cmdline = "demo_dos --burst"
                lineage = @("powershell", "demo")
                dns_name = ""
                env = @{ "DEMO_MODE" = "true" }
            }

            $incidentPayload = [ordered]@{
                timestamp = $tsUtc.ToString("o")
                decision = @{ action = $action; reasons = @("demo burst for dashboard validation"); severity = if ($action -eq "kill") { "critical" } else { "high" } }
                pid = $pid
                process_name = $procName
                context = @{ cmdline = "demo_dos --burst"; lineage = @("powershell", "demo") }
                inference = @{ anomaly_score = 0.97; label = "anomaly" }
                signature_detected = $true
                signature_reasons = @("demo burst")
                signature_tags = @("dos", "reverse_shell")
                signature_critical = $true
                latest_event = $eventPayload
                kill_enforced = $false
                kill_mode = "simulated_demo"
                integrity_sha256 = "demo"
            }

            ($eventPayload | ConvertTo-Json -Compress) | Add-Content -Path $eventPath -Encoding utf8
            ($incidentPayload | ConvertTo-Json -Compress -Depth 6) | Add-Content -Path $incidentPath -Encoding utf8
            Start-Sleep -Milliseconds 350
        }
    } -ArgumentList $eventLogPath, (Join-Path $logsDir "incidents.jsonl")

    Write-Host "Demo burst job started with Id=$($demoBurstJob.Id)"
}

try {
    # Run Streamlit in current window.
    & $streamlitExe run .\agentshield\dashboard\app.py
} finally {
    if ($collectorJob) {
        Stop-Job -Id $collectorJob.Id -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Id $collectorJob.Id -ErrorAction SilentlyContinue | Out-Null
    }
    if ($tcpSamplerJob) {
        Stop-Job -Id $tcpSamplerJob.Id -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Id $tcpSamplerJob.Id -ErrorAction SilentlyContinue | Out-Null
    }
    if ($demoBurstJob) {
        Stop-Job -Id $demoBurstJob.Id -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Id $demoBurstJob.Id -ErrorAction SilentlyContinue | Out-Null
    }
}
