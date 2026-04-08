# verify-sdp.ps1
$ErrorActionPreference = "Stop"

$composeFile = "docker-compose.sdp.yml"
$controllerBase = "http://127.0.0.1:7001"
$gatewayBase = "https://127.0.0.1:8088"
$internalGatewayHealth = "https://127.0.0.1:3443/health"
$spaHost = "127.0.0.1"
$spaPort = "62201"
$clientId = "admin-laptop-01"
$clientSecret = "admin_agent_secret_demo"
$spaSecret = "admin_spa_secret_demo"
$serviceId = "hospital-backend-app"
$adminEmail = "admin@hospital.com"
$adminPass = "Admin@123"
$adminMfaSecret = "PVSU22Z3OBIWIZKXF52GWNDHLJJUMMSJKJJFI7L2IVAS44CJF42Q"
$caCert = "certs\ca\ca.crt"
$clientCert = "certs\clients\admin-laptop-01.crt"
$clientKey = "certs\clients\admin-laptop-01.key"

function Wait-Http200 {
    param(
        [string]$Url,
        [int]$TimeoutSec = 180,
        [switch]$UseMtls
    )
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSec) {
        try {
            if ($UseMtls) {
                $code = & curl.exe --silent --output NUL --write-out "%{http_code}" --cacert $caCert --cert $clientCert --key $clientKey $Url
                if ([int]$code -eq 200) { return $true }
            } else {
                $r = Invoke-WebRequest -Uri $Url -Method GET -UseBasicParsing -TimeoutSec 5
                if ($r.StatusCode -eq 200) { return $true }
            }
        } catch {}
        Start-Sleep -Seconds 2
    }
    throw "Timeout waiting for $Url"
}

function Invoke-CurlJson {
    param(
        [string]$Url,
        [string]$Method = "GET",
        [string]$Body = "",
        [hashtable]$Headers = @{},
        [switch]$UseMtls
    )

    $args = @("--silent", "--show-error", "--fail-with-body")
    if ($UseMtls) {
        $args += @("--cacert", $caCert, "--cert", $clientCert, "--key", $clientKey)
    }
    foreach ($k in $Headers.Keys) { $args += @("-H", "${k}: $($Headers[$k])") }
    if ($Method -ne "GET") {
        $args += @("-X", $Method)
        if ($Body) {
            $args += @("-H", "Content-Type: application/json", "-d", $Body)
        }
    }
    $args += $Url

    $raw = & curl.exe @args
    if ($LASTEXITCODE -ne 0) {
        throw "curl failed for $Url"
    }
    return $raw | ConvertFrom-Json
}

function Get-HttpCode {
    param(
        [string]$Url,
        [string]$Method = "GET",
        [string]$Body = "",
        [hashtable]$Headers = @{},
        [switch]$UseMtls
    )

    $args = @("--silent", "--output", "NUL", "--write-out", "%{http_code}")
    if ($UseMtls) {
        $args += @("--cacert", $caCert, "--cert", $clientCert, "--key", $clientKey)
    }
    foreach ($k in $Headers.Keys) { $args += @("-H", "${k}: $($Headers[$k])") }
    if ($Method -ne "GET") {
        $args += @("-X", $Method)
        if ($Body) { $args += @("-d", $Body) }
    }
    $args += $Url
    $code = & curl.exe @args
    return [int]$code
}

Write-Host "`n[0/9] Generating demo certificates..." -ForegroundColor Cyan
powershell -ExecutionPolicy Bypass -File .\generate-demo-certs.ps1

Write-Host "[1/9] Starting SDP stack..." -ForegroundColor Cyan
docker compose -f $composeFile down | Out-Null
docker compose -f $composeFile up -d

Write-Host "[2/9] Waiting for services..." -ForegroundColor Cyan
Wait-Http200 "$controllerBase/health" 240
Wait-Http200 "$gatewayBase/health" 240 -UseMtls
Wait-Http200 "http://127.0.0.1:4000/" 240
Wait-Http200 $internalGatewayHealth 240 -UseMtls
Write-Host "Services are up." -ForegroundColor Green

Write-Host "[3/9] mTLS-only check: protected endpoint without SPA admission should be denied..." -ForegroundColor Cyan
$codeNoSpa = Get-HttpCode -Url "$gatewayBase/api/login" -Method "POST" -Body "{}" -Headers @{ "Content-Type" = "application/json" } -UseMtls
if ($codeNoSpa -ne 403) {
    throw "Expected 403 before SPA admission, got $codeNoSpa"
}
Write-Host "PASS: mTLS client without SPA admission denied ($codeNoSpa)." -ForegroundColor Green

Write-Host "[4/9] Sending SPA knock..." -ForegroundColor Cyan
node agents/sdp-client/spa-knock.js --host=$spaHost --port=$spaPort --client-id=$clientId --spa-secret=$spaSecret

Write-Host "[5/9] Login + MFA over mTLS..." -ForegroundColor Cyan
$loginBody = @{ email = $adminEmail; password = $adminPass } | ConvertTo-Json -Compress
$loginResp = Invoke-CurlJson -Url "$gatewayBase/api/login" -Method "POST" -Body $loginBody -Headers @{ "x-sdp-client-id" = $clientId } -UseMtls
if (-not $loginResp.success) { throw "Login failed: $($loginResp.error)" }

$token = $null
if ($loginResp.mfaRequired -eq $true) {
    $mfaCode = docker exec hospital-iam node -e "const s=require('speakeasy'); console.log(s.totp({secret:'$adminMfaSecret',encoding:'base32'}));"
    $mfaCode = ($mfaCode | Select-Object -Last 1).Trim()
    $mfaBody = @{ email = $adminEmail; code = $mfaCode } | ConvertTo-Json -Compress
    $mfaResp = Invoke-CurlJson -Url "$gatewayBase/api/mfa/verify" -Method "POST" -Body $mfaBody -Headers @{ "x-sdp-client-id" = $clientId } -UseMtls
    if (-not $mfaResp.success) { throw "MFA failed: $($mfaResp.error)" }
    $token = $mfaResp.token
} else {
    $token = $loginResp.token
}
if (-not $token) { throw "No token returned after auth." }
Write-Host "PASS: authenticated and received token." -ForegroundColor Green

Write-Host "[6/9] Request backend service grant from SDP access controller..." -ForegroundColor Cyan
$grantReqBody = @{
    clientId = $clientId
    clientSecret = $clientSecret
    serviceId = $serviceId
    requestedPath = "/api/patients"
    method = "GET"
    userToken = $token
} | ConvertTo-Json -Compress
$grantResp = Invoke-RestMethod -Uri "$controllerBase/connect" -Method POST -ContentType "application/json" -Body $grantReqBody
if (-not $grantResp.ok -or -not $grantResp.grantToken) {
    throw "Expected grant token from access controller."
}
Write-Host "PASS: service grant issued for $($grantResp.service.serviceId)." -ForegroundColor Green

Write-Host "[7/9] SDP check: authenticated request with grant over mTLS should succeed..." -ForegroundColor Cyan
$headers = @{
    Authorization = "Bearer $token"
    "x-sdp-grant" = "$($grantResp.grantToken)"
    "x-sdp-client-id" = $clientId
}
$codeWithGrant = Get-HttpCode -Url "$gatewayBase/api/patients" -Headers $headers -UseMtls
if ($codeWithGrant -ne 200) {
    throw "Expected 200 for authenticated /api/patients with grant, got $codeWithGrant"
}
Write-Host "PASS: authenticated request with grant allowed ($codeWithGrant)." -ForegroundColor Green

Write-Host "[8/9] Verify controller and monitoring state..." -ForegroundColor Cyan
$gw = Invoke-CurlJson -Url "$gatewayBase/health" -UseMtls
$controller = Invoke-RestMethod -Uri "$controllerBase/health" -Method GET
$telemetry = Invoke-RestMethod -Uri "http://127.0.0.1:9090/telemetry" -Method GET
$isolations = Invoke-RestMethod -Uri "http://127.0.0.1:4100/isolations" -Method GET
Write-Host "Gateway TLS enabled: $($gw.tls)" -ForegroundColor Yellow
Write-Host "Registered gateways: $($controller.registeredGateways)" -ForegroundColor Yellow
Write-Host "Registered services: $($controller.registeredServices)" -ForegroundColor Yellow
Write-Host "Active SPA admissions: $($controller.activeSpaAdmissions)" -ForegroundColor Yellow
Write-Host "Telemetry entries: $($telemetry.recentTelemetry.Count)" -ForegroundColor Yellow
Write-Host "Isolation actions: $($isolations.Count)" -ForegroundColor Yellow

Write-Host "[9/9] Container status..." -ForegroundColor Cyan
docker compose -f $composeFile ps

Write-Host "Verification complete." -ForegroundColor Green
Write-Host "To stop: docker compose -f $composeFile down" -ForegroundColor Gray
