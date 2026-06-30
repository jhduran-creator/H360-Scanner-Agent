# HelpDesk 360 Scanner Agent

Agente Go que vive en la LAN del cliente y descubre activos (equipos de
red, servidores, PCs) para reportarlos al cloud HD360 vía HTTPS+HMAC.

**Estado actual (29-jun-2026):** Fase 2 MVP — ICMP ping sweep funcional.
nmap/SNMP/LDAP/WMI/SSH/vCenter vienen en próximas iteraciones (ver
`plans/SPRINT-SCANNER-AGENT.md` en el repo raíz).

## Arquitectura

```
┌─── LAN del cliente ───────────────────────┐
│                                           │
│  ┌──────────────┐ ICMP/SNMP/WMI/SSH      │
│  │ hd360-scanner├──────────────────────►  │ ◄── escanea switches, PCs, servers
│  │  (Go binary) │                         │
│  └──────┬───────┘                         │
└─────────┼─────────────────────────────────┘
          │ HTTPS POST con HMAC
          ▼
   https://{tenant}.helpdesk360.cr/api/v1/scanner-inbound/*
```

## Requisitos

- **Linux**: kernel >= 3.x. Para ICMP privileged, correr como root o
  asignar capability: `sudo setcap 'cap_net_raw=+ep' /usr/local/bin/hd360-scanner`.
- **Windows**: Server 2016+. Correr como **Administrator** (para ICMP +
  futuro WMI).
- **macOS**: 10.15+ (solo para dev/testing — no recomendado en prod).

## Instalación

### Opción A: binario nativo

```bash
# Linux amd64 (ejemplo)
curl -L -o hd360-scanner https://helpdesk360.cr/downloads/hd360-scanner-linux-amd64
chmod +x hd360-scanner
sudo mv hd360-scanner /usr/local/bin/
sudo setcap 'cap_net_raw=+ep' /usr/local/bin/hd360-scanner

# Wizard de setup
hd360-scanner setup --config /etc/hd360-scanner/agent.yaml

# Probar
hd360-scanner discover

# Instalar como servicio (systemd ejemplo)
sudo systemctl enable --now hd360-scanner
```

### Opción B: Docker

```bash
docker run -d \
  --name hd360-scanner \
  --restart unless-stopped \
  --cap-add NET_RAW \
  --network host \
  -v /etc/hd360-scanner:/etc/hd360-scanner:ro \
  hd360-scanner:latest
```

⚠️ `--network host` necesario para que el agente vea la LAN real (no la
network bridge de Docker). `--cap-add NET_RAW` necesario para ICMP raw socket.

## Configuración

El agente lee config de `/etc/hd360-scanner/agent.yaml` (o el path pasado
en `--config`). Ver `configs/agent.yaml.example` para todos los campos.

**Mínimo necesario:**
```yaml
scanner_id: <UUID del scanner creado en cloud>
agent_secret: <secret entregado UNA vez al crear>
cloud_url: https://kuanta.helpdesk360.cr/api/v1
```

También se puede via env vars (útil con Docker):
```
HD360_SCANNER_SCANNER_ID=abc-...
HD360_SCANNER_AGENT_SECRET=...
HD360_SCANNER_CLOUD_URL=https://kuanta.helpdesk360.cr/api/v1
```

## Subcomandos

```
hd360-scanner setup       — wizard interactivo para crear config
hd360-scanner run         — daemon (heartbeat + discovery según schedule)
hd360-scanner discover    — one-shot: heartbeat + scan + report + exit
hd360-scanner version     — print version
```

## Build

```bash
# Local (requiere Go 1.22+)
make build

# Cross-platform (Linux + Windows + Mac, amd64 + arm64)
make build-all

# Vía Docker (sin Go local)
make docker
```

## Seguridad

- **HMAC-SHA256** firma cada request al cloud. Mismo secret que recibís
  al crear el scanner en la UI.
- **TLS 1.2+** outbound al cloud (cert Let's Encrypt wildcard).
- **Credentials de protocolos** (SNMP communities, AD bind, WMI admin,
  SSH keys) viajan **encriptadas** AES-256-GCM y se mantienen
  **solo en memoria** del agente — nunca a disco.
- El agente NO acepta conexiones inbound — solo origina outbound al cloud.
  Cero puertos abiertos en firewall del cliente.

## Troubleshooting

**"Permission denied" al hacer ICMP**: el agente requiere raw socket.
En Linux ejecutar:
```
sudo setcap 'cap_net_raw=+ep' /usr/local/bin/hd360-scanner
```
O correr como root (no recomendado).

**"Timestamp out of range"**: el clock del server local está desfasado
>5 min del cloud. Sync con NTP:
```
sudo systemctl enable --now systemd-timesyncd
```

**"Unknown scanner"**: el scanner_id no existe en el cloud. Posibles
causas: copiado mal, scanner eliminado, rotación de secret pendiente.

## Soporte

Issues y PRs: contactar al equipo HD360.
