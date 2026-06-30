# Instalación — HD360 Scanner Agent

## 1. Pre-requisitos

| Plataforma | Requisitos |
|---|---|
| **Linux** (Ubuntu 20+, Debian 11+, CentOS/RHEL 8+, Alpine 3.18+) | `nmap` instalado (apt/yum/apk). Para ICMP: cap_net_raw o root. |
| **Windows Server 2016+** | nmap opcional (descargar de [nmap.org](https://nmap.org/download.html)). Correr Service como Administrator. |
| **macOS 11+** | Solo para dev/testing. nmap via `brew install nmap`. |
| **Docker** | Cualquier host con Docker 20+. `--cap-add NET_RAW` + `--network host`. |

## 2. Crear scanner en cloud (antes de instalar)

1. Ir a `https://{tu-tenant}.helpdesk360.cr/settings/scanners`
2. Clic **+ Nuevo Scanner** → nombre + descripción
3. **Copiar AHORA** los 3 valores que muestra el modal:
   - Scanner ID (UUID)
   - Agent Secret
   - Cloud URL

⚠️ El secret no se muestra otra vez. Si lo perdés, hay que rotar (botón en el detalle del scanner) y reconfigurar el agente.

## 3. Instalación por plataforma

### Linux (one-liner)

```bash
curl -fsSL https://helpdesk360.cr/downloads/install-linux.sh | sudo bash
sudo hd360-scanner setup --config /etc/hd360-scanner/agent.yaml
sudo systemctl enable --now hd360-scanner
```

Que hace el instalador:
1. `apt/yum/apk install nmap curl ca-certificates`
2. Descarga el binario correcto (amd64 o arm64 auto-detectado)
3. `setcap 'cap_net_raw=+ep'` para ICMP sin root
4. Crea user `hd360-scanner` sin shell
5. Crea `/etc/hd360-scanner/` con perms 750
6. Instala `/etc/systemd/system/hd360-scanner.service`
7. systemd daemon-reload

### Windows Server (PowerShell como Admin)

```powershell
irm https://helpdesk360.cr/downloads/install-windows.ps1 | iex
```

Que hace:
1. Crea `C:\hd360-scanner\`
2. Descarga `hd360-scanner.exe`
3. Wizard interactivo para crear `agent.yaml`
4. Registra Windows Service `Hd360Scanner` con auto-start
5. Inicia el servicio

### Docker

```bash
mkdir -p /etc/hd360-scanner
# Crear /etc/hd360-scanner/agent.yaml a partir del ejemplo

docker run -d \
  --name hd360-scanner \
  --restart unless-stopped \
  --cap-add NET_RAW \
  --network host \
  -v /etc/hd360-scanner:/etc/hd360-scanner:ro \
  ghcr.io/kuanta-bridge/hd360-scanner:latest
```

O con env vars en lugar de volume:
```bash
docker run -d --name hd360-scanner --restart unless-stopped \
  --cap-add NET_RAW --network host \
  -e HD360_SCANNER_SCANNER_ID=<uuid> \
  -e HD360_SCANNER_AGENT_SECRET=<secret> \
  -e HD360_SCANNER_CLOUD_URL=https://kuanta.helpdesk360.cr/api/v1 \
  ghcr.io/kuanta-bridge/hd360-scanner:latest
```

## 4. Configurar rangos + credentials

Una vez el agente esté `Activo` en el cloud (~1 minuto después de iniciar):

1. Ir al detalle del scanner en `/settings/scanners/{id}`
2. **Tab Configuración**:
   - Schedule: `Cada 5 min` / `Hora` / `Diario` / `Manual`
   - Protocolos habilitados: marcar los que aplican a tu LAN
   - Rangos IP: agregar al menos un CIDR (ej: `10.0.0.0/24`)
3. **Tab Credenciales** (opcional según protocolos):
   - SNMP v2c → community string (típicamente `public`)
   - WMI → usuario admin Windows + password
   - SSH → usuario + password o private key
   - LDAP → bind DN + password + base DN
   - vCenter → usuario + password + server URL
4. **Guardar configuración** — se aplica en el siguiente heartbeat (~1 min)

## 5. Validar end-to-end

```bash
# Linux/Mac
sudo journalctl -u hd360-scanner -f

# Windows
Get-EventLog -LogName Application -Source Hd360Scanner -Newest 50
```

Esperás ver logs tipo:
```
INFO  agente iniciado scanner_id=... cloud_url=...
INFO  heartbeat OK ranges=1 protocols=[icmp snmp_v2c]
INFO  ICMP sweep completado cidr=10.0.0.0/24 alive=42
INFO  discovery-report enviado accepted=42 errors=0
```

En el cloud, ir a `/assets/discovered` → deberías ver los 42 activos listos para review/accept.

## 6. Troubleshooting

| Síntoma | Causa | Fix |
|---|---|---|
| `permission denied` en ICMP | Falta cap_net_raw | `sudo setcap 'cap_net_raw=+ep' /usr/local/bin/hd360-scanner` |
| `Timestamp out of range` | Clock skew >5 min | Activar NTP: `sudo systemctl enable --now systemd-timesyncd` |
| `Unknown scanner` | scanner_id mal copiado o eliminado en cloud | Re-crear desde UI cloud |
| `Invalid signature` | secret mal copiado | Rotar secret en UI cloud + reconfigurar agente |
| `nmap: executable file not found` | nmap no instalado en runtime | `apt install nmap` (Linux), descargar de nmap.org (Windows) |
| Sin hosts descubiertos | rangos mal configurados o firewall bloqueando | Probar con un solo /24 conocido + `hd360-scanner discover --log-level debug` |

## 7. Actualización

### Linux
```bash
sudo systemctl stop hd360-scanner
curl -fsSL https://helpdesk360.cr/downloads/install-linux.sh | sudo HD360_SCANNER_VERSION=v1.2.0 bash
sudo systemctl start hd360-scanner
```

### Windows
```powershell
Stop-Service Hd360Scanner
irm https://helpdesk360.cr/downloads/install-windows.ps1 | iex
Start-Service Hd360Scanner
```

### Docker
```bash
docker pull ghcr.io/kuanta-bridge/hd360-scanner:latest
docker restart hd360-scanner
```

## 8. Desinstalación

### Linux
```bash
sudo systemctl disable --now hd360-scanner
sudo rm /usr/local/bin/hd360-scanner /etc/systemd/system/hd360-scanner.service
sudo rm -rf /etc/hd360-scanner
sudo userdel hd360-scanner
```

### Windows
```powershell
Stop-Service Hd360Scanner
sc.exe delete Hd360Scanner
Remove-Item -Recurse C:\hd360-scanner
```

### Docker
```bash
docker rm -f hd360-scanner
docker rmi ghcr.io/kuanta-bridge/hd360-scanner
```
