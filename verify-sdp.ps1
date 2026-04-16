# verify-sdp.ps1
$ErrorActionPreference = "Stop"

$composeFile = "docker-compose.sdp.yml"
$controllerBase = "http://127.0.0.1:7001"
$gatewayBase = "https://localhost:8088"
$internalGatewayHealth = "https://localhost:3443/health"
$spaHost = "127.0.0.1"
$spaPort = "62201"
$clientId = "admin-laptop-01"
$clientSecret = "admin_agent_secret_demo"
$spaSecret = "admin_spa_secret_demo"
$registrationToken = "sdp_register_demo_token"
$serviceId = "hospital-backend-app"
$adminEmail = "admin@hospital.com"
$adminPass = "Admin@123"
$adminMfaSecret = "PVSU22Z3OBIWIZKXF52GWNDHLJJUMMSJKJJFI7L2IVAS44CJF42Q"
$accountantEmail = "accountant@hospital.com"
$accountantPass = "Accountant@123"
$accountantMfaSecret = "IBSG27J4NN3HSZTQGY4SS2DMNRPEGJRZIJFW4423J5WDMUBFEVKA"
$caCert = "certs\ca\ca.crt"
$clientCert = "certs\clients\admin-laptop-01.crt"
$clientKey = "certs\clients\admin-laptop-01.key"

function Invoke-NodeMtls {
    param(
        [string]$Url,
        [string]$Method = "GET",
        [string]$Body = "",
        [hashtable]$Headers = @{}
    )

    $requestFile = [System.IO.Path]::GetTempFileName()
    $nodeScript = @'
const fs = require('fs');
const https = require('https');

const payload = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
const url = new URL(payload.url);
const body = payload.body || '';
const headers = Object.assign({}, payload.headers || {});

if (body && !headers['Content-Type'] && !headers['content-type']) {
  headers['Content-Type'] = 'application/json';
}
if (body && !headers['Content-Length']) {
  headers['Content-Length'] = Buffer.byteLength(body);
}

const req = https.request({
  hostname: url.hostname,
  port: url.port || 443,
  path: url.pathname + url.search,
  method: payload.method || 'GET',
  headers,
  ca: fs.readFileSync(payload.caCert),
  cert: fs.readFileSync(payload.clientCert),
  key: fs.readFileSync(payload.clientKey),
  rejectUnauthorized: true,
  servername: url.hostname
}, (res) => {
  let raw = '';
  res.on('data', chunk => { raw += chunk; });
  res.on('end', () => {
    process.stdout.write(JSON.stringify({ statusCode: res.statusCode || 0, body: raw }));
  });
});

req.setTimeout(15000, () => {
  req.destroy(new Error('request timed out'));
});
req.on('error', (err) => {
  process.stderr.write(err.message);
  process.exit(2);
});
if (body) req.write(body);
req.end();
'@

    try {
        @{
            url = $Url
            method = $Method
            body = $Body
            headers = $Headers
            caCert = $caCert
            clientCert = $clientCert
            clientKey = $clientKey
        } | ConvertTo-Json -Compress | Set-Content -Path $requestFile -Encoding ascii

        $raw = node -e $nodeScript $requestFile
        if ($LASTEXITCODE -ne 0) {
            throw "Node mTLS request failed for $Url"
        }
        return $raw | ConvertFrom-Json
    } finally {
        Remove-Item -LiteralPath $requestFile -Force -ErrorAction SilentlyContinue
    }
}

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
                $r = Invoke-NodeMtls -Url $Url
                if ([int]$r.statusCode -eq 200) { return $true }
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
        $mtlsResp = Invoke-NodeMtls -Url $Url -Method $Method -Body $Body -Headers $Headers
        if ([int]$mtlsResp.statusCode -ge 400) {
            throw "mTLS request failed for $Url with HTTP $($mtlsResp.statusCode): $($mtlsResp.body)"
        }
        return $mtlsResp.body | ConvertFrom-Json
    }

    foreach ($k in $Headers.Keys) { $args += @("-H", "${k}: $($Headers[$k])") }
    if ($Method -ne "GET") {
        $args += @("-X", $Method)
        if ($Body) { $args += @("-H", "Content-Type: application/json", "-d", $Body) }
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
        $mtlsResp = Invoke-NodeMtls -Url $Url -Method $Method -Body $Body -Headers $Headers
        return [int]$mtlsResp.statusCode
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

function Get-TotpCode {
    param([string]$Secret)
    $code = docker exec hospital-iam node -e "const s=require('speakeasy'); console.log(s.totp({secret:'$Secret',encoding:'base32'}));"
    return ($code | Select-Object -Last 1).Trim()
}

function Login-WithMfa {
    param(
        [string]$Email,
        [string]$Password,
        [string]$MfaSecret,
        [string]$ClientIdHeader
    )

    $loginBody = @{ email = $Email; password = $Password } | ConvertTo-Json -Compress
    $loginResp = Invoke-CurlJson -Url "$gatewayBase/api/login" -Method "POST" -Body $loginBody -Headers @{ "x-sdp-client-id" = $ClientIdHeader } -UseMtls
    if (-not $loginResp.success) { throw "Login failed for ${Email}: $($loginResp.error)" }

    if ($loginResp.mfaRequired -eq $true) {
        $mfaCode = Get-TotpCode -Secret $MfaSecret
        $mfaBody = @{ email = $Email; code = $mfaCode } | ConvertTo-Json -Compress
        $mfaResp = Invoke-CurlJson -Url "$gatewayBase/api/mfa/verify" -Method "POST" -Body $mfaBody -Headers @{ "x-sdp-client-id" = $ClientIdHeader } -UseMtls
        if (-not $mfaResp.success) { throw "MFA failed for ${Email}: $($mfaResp.error)" }
        return $mfaResp.token
    }

    return $loginResp.token
}

function Invoke-GrantRequest {
    param(
        [string]$UserToken,
        [string]$RequestedPath
    )

    $grantReqBody = @{
        clientId = $clientId
        clientSecret = $clientSecret
        serviceId = $serviceId
        requestedPath = $RequestedPath
        method = "GET"
        userToken = $UserToken
    } | ConvertTo-Json -Compress

    return Invoke-RestMethod -Uri "$controllerBase/connect" -Method POST -ContentType "application/json" -Body $grantReqBody
}

function Test-GrantDenied403 {
    param(
        [string]$UserToken,
        [string]$RequestedPath
    )

    $grantReqBody = @{
        clientId = $clientId
        clientSecret = $clientSecret
        serviceId = $serviceId
        requestedPath = $RequestedPath
        method = "GET"
        userToken = $UserToken
    } | ConvertTo-Json -Compress

    $request = [System.Net.HttpWebRequest]::Create("$controllerBase/connect")
    $request.Method = "POST"
    $request.ContentType = "application/json"
    $request.Timeout = 5000

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($grantReqBody)
    $request.ContentLength = $bytes.Length
    $stream = $request.GetRequestStream()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Close()

    try {
        $response = $request.GetResponse()
        $response.Close()
        return $false
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            $_.Exception.Response.Close()
            return $statusCode -eq 403
        }
        throw
    }
}

function Get-NoMtlsCurlCode {
    param([string]$Url)
    $output = & curl.exe --silent --output NUL --write-out "%{http_code}" --insecure $Url
    return @{ exitCode = $LASTEXITCODE; httpCode = "$output" }
}

Write-Host "`n[0/13] Generating demo certificates..." -ForegroundColor Cyan
powershell -ExecutionPolicy Bypass -File .\generate-demo-certs.ps1

Write-Host "[1/13] Starting SDP stack..." -ForegroundColor Cyan
docker compose -f $composeFile down | Out-Null
docker compose -f $composeFile up -d

Write-Host "[2/13] Waiting for services..." -ForegroundColor Cyan
Wait-Http200 "$controllerBase/health" 240
Wait-Http200 "$gatewayBase/health" 240 -UseMtls
Wait-Http200 $internalGatewayHealth 240 -UseMtls
Write-Host "Services are up." -ForegroundColor Green

Write-Host "[3/13] Dark service check: no mTLS certificate should be rejected at TLS..." -ForegroundColor Cyan
$noMtls = Get-NoMtlsCurlCode -Url "$gatewayBase/api/health"
if ($noMtls.exitCode -eq 0 -and $noMtls.httpCode -ne "000") {
    throw "Expected TLS rejection without client cert, got curl exit $($noMtls.exitCode) and HTTP $($noMtls.httpCode)"
}
Write-Host "PASS: request without mTLS certificate was rejected (curl=$($noMtls.exitCode), http=$($noMtls.httpCode))." -ForegroundColor Green

Write-Host "[4/13] Dark service check: protected endpoint without SPA admission should be denied..." -ForegroundColor Cyan
$codeNoSpa = Get-HttpCode -Url "$gatewayBase/api/login" -Method "POST" -Body "{}" -Headers @{ "Content-Type" = "application/json" } -UseMtls
if ($codeNoSpa -ne 403) {
    throw "Expected 403 before SPA admission, got $codeNoSpa"
}
Write-Host "PASS: mTLS client without SPA admission denied ($codeNoSpa)." -ForegroundColor Green

Write-Host "[5/13] Sending SPA knock..." -ForegroundColor Cyan
node agents/sdp-client/spa-knock.js --host=$spaHost --port=$spaPort --client-id=$clientId --spa-secret=$spaSecret

Write-Host "[6/13] Login + MFA over mTLS as admin..." -ForegroundColor Cyan
$token = Login-WithMfa -Email $adminEmail -Password $adminPass -MfaSecret $adminMfaSecret -ClientIdHeader $clientId
if (-not $token) { throw "No token returned after auth." }
Write-Host "PASS: authenticated and received token." -ForegroundColor Green

Write-Host "[7/13] Dark service check: authenticated request without grant should be denied..." -ForegroundColor Cyan
$headersNoGrant = @{
    Authorization = "Bearer $token"
    "x-sdp-client-id" = $clientId
}
$codeNoGrant = Get-HttpCode -Url "$gatewayBase/api/patients" -Headers $headersNoGrant -UseMtls
if ($codeNoGrant -ne 403) {
    throw "Expected 403 without service grant, got $codeNoGrant"
}
Write-Host "PASS: authenticated request without grant denied ($codeNoGrant)." -ForegroundColor Green

Write-Host "[8/13] Dark service check: wrong role should be denied a backend grant..." -ForegroundColor Cyan
$accountantToken = Login-WithMfa -Email $accountantEmail -Password $accountantPass -MfaSecret $accountantMfaSecret -ClientIdHeader $clientId
if (-not $accountantToken) { throw "No accountant token returned after auth." }
$accountantGrantDenied = Test-GrantDenied403 -UserToken $accountantToken -RequestedPath "/api/audit"
if (-not $accountantGrantDenied) {
    throw "Expected accountant grant request to be denied with HTTP 403, but a grant was issued."
}
Write-Host "PASS: wrong-role grant request denied (HTTP 403)." -ForegroundColor Green

Write-Host "[9/13] Request backend service grant from SDP access controller..." -ForegroundColor Cyan
$grantResp = Invoke-GrantRequest -UserToken $token -RequestedPath "/api/patients"
if (-not $grantResp.ok -or -not $grantResp.grantToken) {
    throw "Expected grant token from access controller."
}
Write-Host "PASS: service grant issued for $($grantResp.service.serviceId)." -ForegroundColor Green

Write-Host "[10/13] SDP check: valid SPA + mTLS + grant + role should succeed..." -ForegroundColor Cyan
$headers = @{
    Authorization = "Bearer $token"
    "x-sdp-grant" = "$($grantResp.grantToken)"
    "x-sdp-client-id" = $clientId
}
$codeWithGrant = 0
$startGrantCheck = Get-Date
while (((Get-Date) - $startGrantCheck).TotalSeconds -lt 90) {
    $codeWithGrant = Get-HttpCode -Url "$gatewayBase/api/patients" -Headers $headers -UseMtls
    if ($codeWithGrant -eq 200) { break }
    Start-Sleep -Seconds 2
}
if ($codeWithGrant -ne 200) {
    throw "Expected 200 for authenticated /api/patients with grant, got $codeWithGrant"
}
Write-Host "PASS: authenticated request with grant allowed ($codeWithGrant)." -ForegroundColor Green

Write-Host "[11/13] Simulating quarantine response: revoke active SDP access for the workstation..." -ForegroundColor Cyan
$alertBody = @{
    severity = "HIGH"
    event = "ML_RULE_CORRELATED"
    hostId = "admin-laptop-01"
    details = @{
        userEmail = $adminEmail
        userRole = "admin"
        sdpClientId = $clientId
        detection_type = "verify-sdp"
    }
} | ConvertTo-Json -Compress -Depth 5
$alertResp = Invoke-RestMethod -Uri "http://127.0.0.1:4100/alert" -Method POST -ContentType "application/json" -Body $alertBody
if (-not $alertResp.ok) {
    throw "Expected response-controller to accept quarantine simulation."
}
$codeAfterRevoke = Get-HttpCode -Url "$gatewayBase/api/patients" -Headers $headers -UseMtls
if ($codeAfterRevoke -ne 403) {
    throw "Expected 403 after SDP revocation, got $codeAfterRevoke"
}
Write-Host "PASS: quarantine-driven SDP revocation blocked the old session ($codeAfterRevoke)." -ForegroundColor Green

Write-Host "[12/13] Verify controller and audit state..." -ForegroundColor Cyan
$gw = Invoke-CurlJson -Url "$gatewayBase/health" -UseMtls
$controller = Invoke-RestMethod -Uri "$controllerBase/health" -Method GET
$telemetry = Invoke-RestMethod -Uri "http://127.0.0.1:9090/telemetry" -Method GET
$isolations = Invoke-RestMethod -Uri "http://127.0.0.1:4100/isolations" -Method GET
$audit = Invoke-RestMethod -Uri "$controllerBase/audit/recent?limit=12" -Method GET -Headers @{ "x-registration-token" = $registrationToken }
Write-Host "Gateway TLS enabled: $($gw.tls)" -ForegroundColor Yellow
Write-Host "Registered gateways: $($controller.registeredGateways)" -ForegroundColor Yellow
Write-Host "Registered services: $($controller.registeredServices)" -ForegroundColor Yellow
Write-Host "Active SPA admissions: $($controller.activeSpaAdmissions)" -ForegroundColor Yellow
Write-Host "Active issued grants: $($controller.activeIssuedGrants)" -ForegroundColor Yellow
Write-Host "Recent SDP audit events: $($audit.events.Count)" -ForegroundColor Yellow
Write-Host "Telemetry entries: $($telemetry.recentTelemetry.Count)" -ForegroundColor Yellow
Write-Host "Isolation actions: $($isolations.Count)" -ForegroundColor Yellow

Write-Host "[13/13] Container status..." -ForegroundColor Cyan
docker compose -f $composeFile ps

Write-Host "Verification complete." -ForegroundColor Green
Write-Host "To stop: docker compose -f $composeFile down" -ForegroundColor Gray
