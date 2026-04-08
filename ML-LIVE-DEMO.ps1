$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$mlDir = Join-Path $repoRoot 'ml-engine'
$dataFile = Join-Path $mlDir 'data\Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet'
$benignPayloadPath = Join-Path $mlDir 'benign_payload_live_demo.json'
$attackPayloadPath = Join-Path $mlDir 'attack_payload_live_demo.json'

Write-Host "Starting ML live demo from $repoRoot" -ForegroundColor Cyan

if (-not (Test-Path $benignPayloadPath) -or -not (Test-Path $attackPayloadPath)) {
    throw "Required payload files are missing. Expected:`n$benignPayloadPath`n$attackPayloadPath"
}

$job = Start-Job -ScriptBlock {
    Set-Location 'd:\FINAL_YEAR\fypmodif-main\ml-engine'
    @'
import app

app.load_model()
app.rf_model.n_jobs = 1
app.app.run(host="127.0.0.1", port=5000, debug=False)
'@ | python -
}

Start-Sleep -Seconds 8

Write-Host "Using saved demo payloads:" -ForegroundColor DarkCyan
Write-Host "  $benignPayloadPath"
Write-Host "  $attackPayloadPath"

try {
    Write-Host "`n=== HEALTH ===" -ForegroundColor Cyan
    $health = Invoke-WebRequest -UseBasicParsing http://127.0.0.1:5000/health
    $health.Content

    Write-Host "`n=== BENIGN PREDICTION ===" -ForegroundColor Yellow
    $benign = Invoke-WebRequest -UseBasicParsing -Uri http://127.0.0.1:5000/predict -Method POST -ContentType 'application/json' -InFile $benignPayloadPath
    $benign.Content

    Write-Host "`n=== ATTACK PREDICTION ===" -ForegroundColor Red
    $attack = Invoke-WebRequest -UseBasicParsing -Uri http://127.0.0.1:5000/predict -Method POST -ContentType 'application/json' -InFile $attackPayloadPath
    $attack.Content

    Write-Host "`nDemo finished. Review the JSON blocks above for the live results." -ForegroundColor Green
    Write-Host "Payloads used:" -ForegroundColor DarkCyan
    Write-Host "  $benignPayloadPath"
    Write-Host "  $attackPayloadPath"
}
finally {
    Stop-Job $job -ErrorAction SilentlyContinue | Out-Null
    Remove-Job $job -Force -ErrorAction SilentlyContinue
}
