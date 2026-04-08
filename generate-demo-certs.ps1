$ErrorActionPreference = "Stop"

$baseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$certRoot = Join-Path $baseDir "certs"
$caDir = Join-Path $certRoot "ca"
$extDir = Join-Path $certRoot "external-gateway"
$intDir = Join-Path $certRoot "internal-gateway"
$clientDir = Join-Path $certRoot "clients"

foreach ($dir in @($certRoot, $caDir, $extDir, $intDir, $clientDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}

function Write-ExtFile {
    param(
        [string]$Path,
        [string[]]$DnsNames,
        [string]$ExtUsage
    )

    $lines = @(
        "subjectAltName=@alt_names",
        "extendedKeyUsage=$ExtUsage",
        "keyUsage=digitalSignature,keyEncipherment",
        "",
        "[alt_names]"
    )

    for ($i = 0; $i -lt $DnsNames.Length; $i++) {
        $lines += "DNS.$($i + 1)=$($DnsNames[$i])"
    }

    Set-Content -Path $Path -Value ($lines -join "`n") -Encoding ascii
}

function New-SignedCertificate {
    param(
        [string]$Name,
        [string]$Cn,
        [string[]]$DnsNames,
        [string]$TargetDir,
        [string]$ExtUsage
    )

    $key = Join-Path $TargetDir "$Name.key"
    $csr = Join-Path $TargetDir "$Name.csr"
    $crt = Join-Path $TargetDir "$Name.crt"
    $ext = Join-Path $TargetDir "$Name.ext"

    Write-ExtFile -Path $ext -DnsNames $DnsNames -ExtUsage $ExtUsage

    & openssl genrsa -out $key 2048 | Out-Null
    & openssl req -new -key $key -out $csr -subj "/CN=$Cn" | Out-Null
    & openssl x509 -req -in $csr -CA (Join-Path $caDir "ca.crt") -CAkey (Join-Path $caDir "ca.key") -CAcreateserial -out $crt -days 825 -sha256 -extfile $ext | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed while creating $Name"
    }
}

$caKey = Join-Path $caDir "ca.key"
$caCrt = Join-Path $caDir "ca.crt"
if (-not ((Test-Path $caKey) -and (Test-Path $caCrt))) {
    & openssl genrsa -out $caKey 2048 | Out-Null
    & openssl req -x509 -new -nodes -key $caKey -sha256 -days 3650 -out $caCrt -subj "/CN=Hospital SDP Demo CA" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed while creating CA"
    }
}

New-SignedCertificate -Name "external-gateway-server" -Cn "external-api-gateway" -DnsNames @("api-gateway", "localhost", "127.0.0.1") -TargetDir $extDir -ExtUsage "serverAuth"
New-SignedCertificate -Name "external-gateway-client" -Cn "external-api-gateway-client" -DnsNames @("external-api-gateway-client") -TargetDir $extDir -ExtUsage "clientAuth"
New-SignedCertificate -Name "internal-gateway-server" -Cn "backend-internal-gateway" -DnsNames @("backend-internal-gateway", "localhost", "127.0.0.1") -TargetDir $intDir -ExtUsage "serverAuth"
New-SignedCertificate -Name "admin-laptop-01" -Cn "admin-laptop-01" -DnsNames @("admin-laptop-01") -TargetDir $clientDir -ExtUsage "clientAuth"
New-SignedCertificate -Name "doctor-laptop-01" -Cn "doctor-laptop-01" -DnsNames @("doctor-laptop-01") -TargetDir $clientDir -ExtUsage "clientAuth"

Write-Host "Demo certificates generated under $certRoot" -ForegroundColor Green
