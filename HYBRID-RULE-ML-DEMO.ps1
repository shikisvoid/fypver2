$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$mlDemoScript = Join-Path $repoRoot 'ML-LIVE-DEMO.ps1'
$attackPayloadPath = Join-Path $repoRoot 'ml-engine\attack_payload_live_demo.json'
$hybridPayloadPath = Join-Path $repoRoot 'hybrid-attack-demo.json'

Write-Host "Starting hybrid Rule + ML demo from $repoRoot" -ForegroundColor Cyan

if (-not (Test-Path $mlDemoScript)) {
    throw "Missing ML demo script: $mlDemoScript"
}

if (-not (Test-Path $attackPayloadPath)) {
    throw "Missing attack payload: $attackPayloadPath"
}

Write-Host "`nStep 1: Running the existing ML demo first" -ForegroundColor Yellow
powershell -ExecutionPolicy Bypass -File $mlDemoScript

Write-Host "`nStep 2: Building one hybrid attack payload for the monitor pipeline" -ForegroundColor Yellow
$attackPayload = Get-Content $attackPayloadPath -Raw | ConvertFrom-Json

$hybridPayload = [pscustomobject]@{
    hostId = 'demo-hybrid-attack'
    ts = (Get-Date).ToString('o')
    source = 'hybrid-rule-ml-demo'
    userRole = $attackPayload.userRole
    userEmail = $attackPayload.userEmail
    net = [pscustomobject]@{
        src = '172.20.0.25'
        dst = '8.8.8.8'
        port = 443
    }
    network = [pscustomobject]@{
        bytes_sent = 900000
        bytes_recv = 5000
        duration = 15
        packets_per_sec = 450
    }
    processes = @(
        [pscustomobject]@{ pid = 1001; name = 'suspicious.exe'; cmd = 'suspicious.exe --exfil' }
    )
    files = @()
    logs = @()
    alerts = @()
    ml_features = $attackPayload.ml_features
}

$hybridPayload | ConvertTo-Json -Depth 10 | Set-Content $hybridPayloadPath

Write-Host "`nStep 3: Sending the hybrid payload to telemetry ingestion" -ForegroundColor Yellow
Invoke-WebRequest `
    -Uri 'http://localhost:9090/ingest/telemetry' `
    -Method POST `
    -ContentType 'application/json' `
    -InFile $hybridPayloadPath | Out-Null

Write-Host "Payload sent to http://localhost:9090/ingest/telemetry" -ForegroundColor Green
Write-Host "Waiting 8 seconds for traffic-analyzer correlation..." -ForegroundColor DarkCyan
Start-Sleep -Seconds 8

Write-Host "`nStep 4: Recent telemetry entry" -ForegroundColor Yellow
try {
    (Invoke-WebRequest -UseBasicParsing 'http://localhost:9090/telemetry').Content
}
catch {
    Write-Host "Could not fetch /telemetry: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nStep 5: Response controller actions" -ForegroundColor Yellow
try {
    (Invoke-WebRequest -UseBasicParsing 'http://localhost:4100/isolations').Content
}
catch {
    Write-Host "Could not fetch /isolations: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nLive log commands to keep open during the demo:" -ForegroundColor Cyan
Write-Host "  docker logs -f hospital-monitor"
Write-Host "  docker logs -f hospital-response-controller"
Write-Host "`nWhat you should point out:" -ForegroundColor Cyan
Write-Host "  1. ML-LIVE-DEMO.ps1 shows benign = Normal and attack = Malicious"
Write-Host "  2. The injected hybrid payload uses the same ML attack features"
Write-Host "  3. The rule engine also fires because net.dst is 8.8.8.8"
Write-Host "  4. The monitor should emit EXFILTRATION_DETECTED, ML_ANOMALY, and ML_RULE_CORRELATED"
