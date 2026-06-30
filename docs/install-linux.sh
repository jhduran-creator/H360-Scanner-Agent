#!/usr/bin/env bash
# Instalador para Linux (Ubuntu/Debian/CentOS/Alpine).
# Uso:
#   curl -fsSL https://helpdesk360.cr/downloads/install-linux.sh | sudo bash
#   o
#   wget https://helpdesk360.cr/downloads/install-linux.sh -O - | sudo bash

set -euo pipefail

VERSION="${HD360_SCANNER_VERSION:-latest}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) echo "Arquitectura no soportada: $ARCH"; exit 1 ;;
esac

BINARY_URL="https://github.com/jhduran-creator/H360-Scanner-Agent/releases/${VERSION}/download/hd360-scanner-linux-${GOARCH}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/hd360-scanner"
SERVICE_USER="hd360-scanner"

echo "[1/6] Instalando dependencias..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y curl ca-certificates nmap
elif command -v yum >/dev/null 2>&1; then
  yum install -y curl ca-certificates nmap
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache curl ca-certificates nmap
else
  echo "No se detectó apt/yum/apk. Instalá nmap manualmente."
fi

echo "[2/6] Descargando binario (${VERSION}, ${GOARCH})..."
curl -fsSL -o /tmp/hd360-scanner "$BINARY_URL"
chmod +x /tmp/hd360-scanner

echo "[3/6] Instalando en ${INSTALL_DIR}/..."
mv /tmp/hd360-scanner "${INSTALL_DIR}/hd360-scanner"

echo "[4/6] Otorgando capability raw socket (ICMP sin root)..."
setcap 'cap_net_raw=+ep' "${INSTALL_DIR}/hd360-scanner"

echo "[5/6] Creando usuario de servicio + directorio config..."
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /bin/false "${SERVICE_USER}"
fi
mkdir -p "${CONFIG_DIR}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"

echo "[6/6] Instalando systemd unit (no habilitado todavía)..."
SYSTEMD_UNIT_URL="https://helpdesk360.cr/downloads/hd360-scanner.service"
curl -fsSL -o /etc/systemd/system/hd360-scanner.service "$SYSTEMD_UNIT_URL"
systemctl daemon-reload

cat <<EOF

=============================================================
INSTALACIÓN COMPLETA

Próximos pasos:
  1. Crear config interactivo:
     sudo hd360-scanner setup --config ${CONFIG_DIR}/agent.yaml

  2. Probar one-shot:
     sudo -u ${SERVICE_USER} hd360-scanner discover --config ${CONFIG_DIR}/agent.yaml

  3. Iniciar como servicio:
     sudo systemctl enable --now hd360-scanner

  4. Ver logs:
     sudo journalctl -u hd360-scanner -f
=============================================================
EOF
