//go:build !windows
// +build !windows

// Stub para platformas no-Windows. WMI requiere PowerShell + Win RM,
// que solo está disponible nativo en Windows. Para usar WMI con un
// agente Linux/Mac habría que implementar winrm vía librería externa
// (github.com/masterzen/winrm) — TODO en iteración futura.
package wmi

import (
	"context"
	"fmt"
	"time"
)

// Creds — definido en el otro archivo build tag
type Creds struct {
	Username string
	Password string
	Domain   string
}

// HostInfo — definido en el otro archivo build tag
type HostInfo struct {
	IP           string
	Hostname     string
	OSName       string
	OSVersion    string
	OSArch       string
	Manufacturer string
	Model        string
	Serial       string
	CPUModel     string
	CPUCores     int
	RAMGb        float64
	DiskGb       float64
	Software     []SoftwarePackage
}

type SoftwarePackage struct {
	Name        string
	Version     string
	Publisher   string
	InstallDate string
}

// Collect en plataformas no-Windows devuelve error explicativo.
func Collect(_ context.Context, ip string, _ Creds, _ time.Duration) (*HostInfo, error) {
	return nil, fmt.Errorf("WMI no soportado en este agente (compilado para no-Windows). Para escanear %s con WMI, instalá el agente en un Windows Server", ip)
}
