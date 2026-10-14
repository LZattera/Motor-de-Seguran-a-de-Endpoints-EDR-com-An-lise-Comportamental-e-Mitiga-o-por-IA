<#
.SYNOPSIS
    Gera a PKI de desenvolvimento do EDR Agent (CA, certs mTLS e chaves de assinatura).

.DESCRIPTION
    - Executa scripts/DevPki.cs (app de arquivo único do .NET 10) para gerar os artefatos em certs/.
    - Gera uma senha aleatória para os .pfx e grava em dotnet user-secrets (nunca em arquivo versionado).

.EXAMPLE
    .\scripts\New-DevPki.ps1
    .\scripts\New-DevPki.ps1 -AgentId MEU-PC -Force
#>
[CmdletBinding()]
param(
    [string]$AgentId = $env:COMPUTERNAME,
    [string]$ServerDnsName = 'localhost',
    [int]$ValidDays = 365,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$projectDir = Split-Path -Parent $PSScriptRoot
$outDir     = Join-Path $projectDir 'certs'

if ((Test-Path $outDir) -and (Get-ChildItem $outDir -File) -and -not $Force) {
    throw "A pasta '$outDir' já contém arquivos. Use -Force para regenerar a PKI."
}

# Senha aleatória de 32 caracteres (Base64 de 24 bytes)
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = [Convert]::ToBase64String($bytes)

dotnet run --file (Join-Path $PSScriptRoot 'DevPki.cs') -- $outDir $AgentId $ServerDnsName $ValidDays $password
if ($LASTEXITCODE -ne 0) { throw "Falha ao gerar a PKI." }

dotnet user-secrets set 'Security:ClientCertificate:Password' $password --project $projectDir | Out-Null
dotnet user-secrets set 'Security:AgentId' $AgentId --project $projectDir | Out-Null

Write-Host ""
Write-Host "Senha do agent.pfx gravada em user-secrets (Security:ClientCertificate:Password)." -ForegroundColor Green
Write-Host "AgentId: $AgentId" -ForegroundColor Green
Write-Host "Senha do server.pfx (guarde para o backend): $password" -ForegroundColor Yellow
Write-Host "signing-private.pem pertence ao BACKEND. Não copie para máquinas com agente." -ForegroundColor Yellow
