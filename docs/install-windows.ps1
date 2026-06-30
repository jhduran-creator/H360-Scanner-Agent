# Instalador PowerShell para Windows Server.
# Correr como Administrator:
#   irm https://helpdesk360.cr/downloads/install-windows.ps1 | iex

$ErrorActionPreference = 'Stop'

$VERSION = if ($env:HD360_SCANNER_VERSION) { $env:HD360_SCANNER_VERSION } else { 'latest' }
$BinaryURL = "https://github.com/kuanta-bridge/helpdesk360/releases/$VERSION/download/hd360-scanner-windows-amd64.exe"
$InstallDir = 'C:\hd360-scanner'
$ConfigPath = "$InstallDir\agent.yaml"

Write-Host "[1/5] Creando directorio $InstallDir..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "[2/5] Descargando binario ($VERSION)..."
Invoke-WebRequest -Uri $BinaryURL -OutFile "$InstallDir\hd360-scanner.exe"

Write-Host "[3/5] Verificando instalación de nmap..."
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Warning "nmap no está instalado. Descargalo de https://nmap.org/download.html antes de usar el protocolo nmap."
    Write-Warning "Sin nmap, los demás protocolos (ICMP, SNMP, WMI, SSH, LDAP, vCenter) funcionan igual."
}

Write-Host "[4/5] Wizard de configuración..."
& "$InstallDir\hd360-scanner.exe" setup --config $ConfigPath
if ($LASTEXITCODE -ne 0) {
    Write-Error "Setup falló — revisá los valores"
    exit 1
}

Write-Host "[5/5] Instalando como Windows Service 'Hd360Scanner'..."
$existing = Get-Service -Name 'Hd360Scanner' -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service Hd360Scanner -Force -ErrorAction SilentlyContinue
    sc.exe delete Hd360Scanner | Out-Null
    Start-Sleep -Seconds 2
}
sc.exe create Hd360Scanner binPath= "`"$InstallDir\hd360-scanner.exe`" run --config `"$ConfigPath`"" start= auto | Out-Null
sc.exe description Hd360Scanner "HelpDesk 360 LAN Discovery Agent" | Out-Null
Start-Service Hd360Scanner

Write-Host ""
Write-Host "=============================================================" -ForegroundColor Green
Write-Host "INSTALACIÓN COMPLETA" -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "El servicio 'Hd360Scanner' está corriendo. Verificá con:"
Write-Host "  Get-Service Hd360Scanner"
Write-Host "  Get-EventLog -LogName Application -Source Hd360Scanner -Newest 20"
Write-Host ""
