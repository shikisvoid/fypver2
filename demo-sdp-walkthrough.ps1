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
$segmentId = "backend-clinical-segment"
$adminEmail = "admin@hospital.com"
$adminPass = "Admin@123"
$adminMfaSecret = "PVSU22Z3OBIWIZKXF52GWNDHLJJUMMSJKJJFI7L2IVAS44CJF42Q"
$accountantEmail = "accountant@hospital.com"
$accountantPass = "Accountant@123"
$accountantMfaSecret = "IBSG27J4NN3HSZTQGY4SS2DMNRPEGJRZIJFW4423J5WDMUBFEVKA"
$caCert = "certs\ca\ca.crt"
$clientCert = "certs\clients\admin-laptop-01.crt"
$clientKey = "certs\clients\admin-laptop-01.key"
$auditLogFile = "spa-controller\audit.log"
$stateFile = "spa-controller\state.json"

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

req.setTimeout(5000, () => {
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

    if ($UseMtls) {
        $mtlsResp = Invoke-NodeMtls -Url $Url -Method $Method -Body $Body -Headers $Headers
        if ([int]$mtlsResp.statusCode -ge 400) {
            throw "mTLS request failed for $Url with HTTP $($mtlsResp.statusCode): $($mtlsResp.body)"
        }
        return $mtlsResp.body | ConvertFrom-Json
    }

    $args = @("--silent", "--show-error", "--fail-with-body")
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

    if ($UseMtls) {
        $mtlsResp = Invoke-NodeMtls -Url $Url -Method $Method -Body $Body -Headers $Headers
        return [int]$mtlsResp.statusCode
    }

    $args = @("--silent", "--output", "NUL", "--write-out", "%{http_code}")
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

function Reset-IamRateLimit {
    Write-Host "IAM rate limit hit. Restarting IAM container and retrying once..." -ForegroundColor Yellow
    docker restart hospital-iam | Out-Null
    Start-Sleep -Seconds 4
    Wait-Http200 "$gatewayBase/health" 120 -UseMtls | Out-Null
}

function Login-WithMfa {
    param(
        [string]$Email,
        [string]$Password,
        [string]$MfaSecret,
        [int]$Attempt = 1
    )

    $loginBody = @{ email = $Email; password = $Password } | ConvertTo-Json -Compress
    try {
        $loginResp = Invoke-CurlJson -Url "$gatewayBase/api/login" -Method "POST" -Body $loginBody -Headers @{ "x-sdp-client-id" = $clientId } -UseMtls
    } catch {
        if ($Attempt -eq 1 -and $_.Exception.Message -match "HTTP 429") {
            Reset-IamRateLimit
            return Login-WithMfa -Email $Email -Password $Password -MfaSecret $MfaSecret -Attempt 2
        }
        throw
    }
    if (-not $loginResp.success) { throw "Login failed for ${Email}: $($loginResp.error)" }

    if ($loginResp.mfaRequired -eq $true) {
        $mfaCode = Get-TotpCode -Secret $MfaSecret
        $mfaBody = @{ email = $Email; code = $mfaCode } | ConvertTo-Json -Compress
        try {
            $mfaResp = Invoke-CurlJson -Url "$gatewayBase/api/mfa/verify" -Method "POST" -Body $mfaBody -Headers @{ "x-sdp-client-id" = $clientId } -UseMtls
        } catch {
            if ($Attempt -eq 1 -and $_.Exception.Message -match "HTTP 429") {
                Reset-IamRateLimit
                return Login-WithMfa -Email $Email -Password $Password -MfaSecret $MfaSecret -Attempt 2
            }
            throw
        }
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

function Show-Step {
    param(
        [string]$Title,
        [string]$WhatToSay
    )

    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host $Title -ForegroundColor Cyan
    Write-Host $WhatToSay -ForegroundColor Yellow
}

function Pause-Demo {
    param([string]$Prompt = "Press Enter to continue")
    Read-Host $Prompt | Out-Null
}

function Reset-DemoArtifacts {
    if (Test-Path $auditLogFile) {
        Remove-Item -LiteralPath $auditLogFile -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $stateFile) {
        Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
    }
}

function Show-RecentAudit {
    param(
        [int]$Limit = 6
    )

    $audit = Invoke-RestMethod -Uri "$controllerBase/audit/recent?limit=$Limit" -Method GET -Headers @{ "x-registration-token" = $registrationToken }
    Write-Host "Recent SDP audit events:" -ForegroundColor Magenta
    foreach ($event in $audit.events) {
        $details = $event.details | ConvertTo-Json -Compress
        Write-Host " - $($event.eventType) :: $details" -ForegroundColor Gray
    }
}

function Show-GrantState {
    $controller = Invoke-RestMethod -Uri "$controllerBase/health" -Method GET
    Write-Host "Active SPA admissions: $($controller.activeSpaAdmissions)" -ForegroundColor Yellow
    Write-Host "Active issued grants: $($controller.activeIssuedGrants)" -ForegroundColor Yellow
    Write-Host "Isolated segments: $($controller.isolatedSegments.Count)" -ForegroundColor Yellow
}

function Show-ContainerNetworks {
    param([string[]]$Containers)

    foreach ($container in $Containers) {
        $networks = docker inspect -f "{{range `$name, `$network := .NetworkSettings.Networks}}{{printf '%s ' `$name}}{{end}}" $container
        Write-Host (" - {0}: {1}" -f $container, ($networks.Trim())) -ForegroundColor Gray
    }
}

function Test-ContainerTcpReachability {
    param(
        [string]$Container,
        [string]$Host,
        [int]$Port
    )

    docker exec $Container node -e "const net=require('net');const socket=net.connect({host:'$Host',port:$Port});socket.setTimeout(1200);socket.on('connect',()=>{socket.end();process.exit(0)});socket.on('timeout',()=>{socket.destroy();process.exit(1)});socket.on('error',()=>process.exit(1));" | Out-Null
    return $LASTEXITCODE -eq 0
}

function Invoke-IsolateSegment {
    param([string]$Reason)

    $body = @{
        serviceId = $serviceId
        segmentId = $segmentId
        reason = $Reason
    } | ConvertTo-Json -Compress
    return Invoke-RestMethod -Uri "$controllerBase/admin/isolate-segment" -Method POST -ContentType "application/json" -Headers @{ "x-registration-token" = $registrationToken } -Body $body
}

function Invoke-ReleaseSegment {
    param([string]$Reason)

    $body = @{
        segmentId = $segmentId
        reason = $Reason
    } | ConvertTo-Json -Compress
    return Invoke-RestMethod -Uri "$controllerBase/admin/release-segment" -Method POST -ContentType "application/json" -Headers @{ "x-registration-token" = $registrationToken } -Body $body
}

Write-Host "`nSDP Demo Walkthrough" -ForegroundColor Green
Write-Host "This script is presentation-friendly and pauses between each scenario." -ForegroundColor Green

Show-Step "Step 0: Start Clean" "We reset the stack, remove old SDP audit/state files, and start from a clean baseline."
Pause-Demo
powershell -ExecutionPolicy Bypass -File .\generate-demo-certs.ps1 | Out-Null
docker compose -f $composeFile down | Out-Null
Reset-DemoArtifacts
docker compose -f $composeFile up -d | Out-Null
Wait-Http200 "$controllerBase/health" 240
Wait-Http200 "$gatewayBase/health" 240 -UseMtls
Wait-Http200 $internalGatewayHealth 240 -UseMtls
Write-Host "Stack is ready." -ForegroundColor Green
Show-GrantState
Pause-Demo

Show-Step "Step 1: Segmented Network Layout" "We show that the edge gateway, internal gateway, backend, and database now sit on different trust-zone networks."
Show-ContainerNetworks -Containers @("hospital-api-gateway", "hospital-backend-internal-gateway", "hospital-backend", "hospital-db")
$edgeToBackend = Test-ContainerTcpReachability -Container "hospital-api-gateway" -Host "hospital-backend" -Port 3000
$internalToBackend = Test-ContainerTcpReachability -Container "hospital-backend-internal-gateway" -Host "hospital-backend" -Port 3000
Write-Host "API gateway -> backend: $edgeToBackend (expected False)" -ForegroundColor Green
Write-Host "Internal gateway -> backend: $internalToBackend (expected True)" -ForegroundColor Green
Pause-Demo

Show-Step "Step 2: No mTLS Certificate" "Without a client certificate, the connection is rejected before the protected SDP flow can continue."
$noMtls = Get-NoMtlsCurlCode -Url "$gatewayBase/api/health"
Write-Host "Result: curl exit=$($noMtls.exitCode), http=$($noMtls.httpCode)" -ForegroundColor Green
Pause-Demo

Show-Step "Step 3: mTLS But No SPA" "The device has a certificate, but it never performed an SPA knock, so the gateway denies the request."
$codeNoSpa = Get-HttpCode -Url "$gatewayBase/api/login" -Method "POST" -Body "{}" -Headers @{ "Content-Type" = "application/json" } -UseMtls
Write-Host "HTTP result: $codeNoSpa" -ForegroundColor Green
Show-RecentAudit
Pause-Demo

Show-Step "Step 4: Perform SPA Knock" "Now the trusted client sends the SPA packet and the access controller creates a temporary admission."
node agents/sdp-client/spa-knock.js --host=$spaHost --port=$spaPort --client-id=$clientId --spa-secret=$spaSecret
Show-RecentAudit
Show-GrantState
Pause-Demo

Show-Step "Step 5: Login As Admin" "Once the device is admitted, the user completes identity authentication and MFA."
$adminToken = Login-WithMfa -Email $adminEmail -Password $adminPass -MfaSecret $adminMfaSecret
Write-Host "Admin token received." -ForegroundColor Green
Pause-Demo

Show-Step "Step 6: No Service Grant Yet" "The device is admitted and the user is authenticated, but backend access is still denied until a service grant is issued."
$headersNoGrant = @{
    Authorization = "Bearer $adminToken"
    "x-sdp-client-id" = $clientId
}
$codeNoGrant = Get-HttpCode -Url "$gatewayBase/api/patients" -Headers $headersNoGrant -UseMtls
Write-Host "HTTP result: $codeNoGrant" -ForegroundColor Green
Show-RecentAudit
Pause-Demo

Show-Step "Step 7: Wrong Role Is Denied" "We keep the same trusted workstation, but log in as an accountant and ask for an admin-only path. Identity-aware policy denies the grant."
$accountantToken = Login-WithMfa -Email $accountantEmail -Password $accountantPass -MfaSecret $accountantMfaSecret
$accountantGrantDenied = Test-GrantDenied403 -UserToken $accountantToken -RequestedPath "/api/audit"
Write-Host "Wrong-role grant denied: $accountantGrantDenied" -ForegroundColor Green
Show-RecentAudit
Pause-Demo

Show-Step "Step 8: Issue Valid Grant" "Now the admin requests a backend grant for `/api/patients`. The access controller checks client credentials, SPA admission, and policy before issuing it."
$grantResp = Invoke-GrantRequest -UserToken $adminToken -RequestedPath "/api/patients"
Write-Host "Grant issued for service: $($grantResp.service.serviceId)" -ForegroundColor Green
Write-Host "Grant expires at: $($grantResp.expiresAt)" -ForegroundColor Green
Show-RecentAudit
Show-GrantState
Pause-Demo

Show-Step "Step 9: Allowed Request" "With valid SPA, mTLS, user auth, and service grant, the protected backend request is allowed."
$headersWithGrant = @{
    Authorization = "Bearer $adminToken"
    "x-sdp-grant" = "$($grantResp.grantToken)"
    "x-sdp-client-id" = $clientId
}
$codeWithGrant = Get-HttpCode -Url "$gatewayBase/api/patients" -Headers $headersWithGrant -UseMtls
Write-Host "HTTP result: $codeWithGrant" -ForegroundColor Green
Show-RecentAudit
Pause-Demo

Show-Step "Step 10: Segment Isolation" "Now we isolate the backend segment itself. New grants into that protected segment are denied even though the user and device are still valid."
$segmentIsolation = Invoke-IsolateSegment -Reason "demo_segment_isolation"
Write-Host "Segment isolation response: revokedGrants=$($segmentIsolation.revokedGrants)" -ForegroundColor Green
$isolatedGrantDenied = Test-GrantDenied403 -UserToken $adminToken -RequestedPath "/api/patients"
Write-Host "Fresh grant denied after segment isolation: $isolatedGrantDenied" -ForegroundColor Green
Show-RecentAudit -Limit 8
Show-GrantState
Pause-Demo

Show-Step "Step 11: Release Segment And Re-Issue Grant" "After releasing the segment, the same authenticated client can request a fresh grant again."
$segmentRelease = Invoke-ReleaseSegment -Reason "demo_segment_release"
Write-Host "Segment released: $($segmentRelease.released)" -ForegroundColor Green
$grantResp = Invoke-GrantRequest -UserToken $adminToken -RequestedPath "/api/patients"
$headersWithGrant["x-sdp-grant"] = "$($grantResp.grantToken)"
Write-Host "Fresh grant issued after release." -ForegroundColor Green
Pause-Demo

Show-Step "Step 12: Quarantine / Revocation" "We simulate a response-controller alert. It revokes IAM access, revokes live grants, and isolates the protected segment."
$alertBody = @{
    severity = "HIGH"
    event = "ML_RULE_CORRELATED"
    hostId = "admin-laptop-01"
    details = @{
        userEmail = $adminEmail
        userRole = "admin"
        sdpClientId = $clientId
        serviceId = $serviceId
        segmentId = $segmentId
        detection_type = "demo-walkthrough"
    }
} | ConvertTo-Json -Compress -Depth 5
$alertResp = Invoke-RestMethod -Uri "http://127.0.0.1:4100/alert" -Method POST -ContentType "application/json" -Body $alertBody
Write-Host "Response controller accepted alert: $($alertResp.ok)" -ForegroundColor Green
$codeAfterRevoke = Get-HttpCode -Url "$gatewayBase/api/patients" -Headers $headersWithGrant -UseMtls
Write-Host "Old grant after revocation returns HTTP: $codeAfterRevoke" -ForegroundColor Green
Show-RecentAudit -Limit 8
Show-GrantState
Pause-Demo "Demo complete. Press Enter to show final reminders"

Write-Host ""
Write-Host "Demo finished." -ForegroundColor Green
Write-Host "Audit log file: $auditLogFile" -ForegroundColor Yellow
Write-Host "To stop the stack: docker compose -f $composeFile down" -ForegroundColor Yellow
