$ErrorActionPreference = "Stop"

$composeFile = "docker-compose.sdp.yml"
$repoRoot = $PSScriptRoot
$workspaceRoot = (Resolve-Path (Join-Path $repoRoot "..\..")).Path
$monitorLogsDir = Join-Path $workspaceRoot "docker-volumes\monitor-logs"
$spaAuditLog = Join-Path $repoRoot "spa-controller\audit.log"
$spaDemoAuditLog = Join-Path $repoRoot "spa-controller\audit-demo.log"
$spaStateFile = Join-Path $repoRoot "spa-controller\state.json"
$spaStateTempFile = Join-Path $repoRoot "spa-controller\state.json.tmp"
$monitorTelemetryLog = Join-Path $monitorLogsDir "telemetry.log"
$monitorAlertsLog = Join-Path $monitorLogsDir "security-alerts.log"
$monitorRoleViolationsLog = Join-Path $monitorLogsDir "role-violations.log"
$monitorTrafficLog = Join-Path $monitorLogsDir "traffic-analysis.log"
$monitorIsolationsFile = Join-Path $monitorLogsDir "isolations.json"
$monitorErrorLog = Join-Path $monitorLogsDir "error.log"

function Ensure-FileContent {
    param(
        [string]$Path,
        [string]$Content = ""
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and !(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    Set-Content -LiteralPath $Path -Value $Content -Encoding ascii
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Reset SDP Demo State" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "[1/5] Stopping containers..." -ForegroundColor Yellow
docker compose -f $composeFile down | Out-Null

Write-Host "[2/5] Clearing SPA controller persisted state..." -ForegroundColor Yellow
Remove-Item -LiteralPath $spaAuditLog -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $spaDemoAuditLog -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $spaStateFile -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $spaStateTempFile -Force -ErrorAction SilentlyContinue

Write-Host "[3/5] Resetting monitor and response-controller logs..." -ForegroundColor Yellow
Ensure-FileContent -Path $monitorTelemetryLog
Ensure-FileContent -Path $monitorAlertsLog
Ensure-FileContent -Path $monitorRoleViolationsLog
Ensure-FileContent -Path $monitorTrafficLog
Ensure-FileContent -Path $monitorErrorLog
Ensure-FileContent -Path $monitorIsolationsFile -Content "[]"

Write-Host "[4/5] Regenerating demo certificates..." -ForegroundColor Yellow
powershell -ExecutionPolicy Bypass -File .\generate-demo-certs.ps1 | Out-Null

Write-Host "[5/5] Starting fresh stack..." -ForegroundColor Yellow
docker compose -f $composeFile up -d

Write-Host ""
Write-Host "Reset complete." -ForegroundColor Green
Write-Host "Expected clean baseline:" -ForegroundColor Yellow
Write-Host "  Active Isolated Segments = 0" -ForegroundColor White
Write-Host "  Registered Gateways = 2" -ForegroundColor White
Write-Host ""
Write-Host "Next:" -ForegroundColor Yellow
Write-Host "  1. Wait 20-40 seconds for services to settle" -ForegroundColor White
Write-Host "  2. Open Prometheus and confirm network-monitoring is UP" -ForegroundColor White
Write-Host "  3. Refresh Grafana dashboard" -ForegroundColor White
