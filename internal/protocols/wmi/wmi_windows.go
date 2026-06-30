//go:build windows
// +build windows

// Package wmi recopila info de un host Windows vía PowerShell + WMI/CIM.
// Solo se compila en builds Windows del agente. En otras plataformas usar
// el stub de wmi_other.go que devuelve error claro.
package wmi

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Creds — credenciales WMI/CIM
type Creds struct {
	Username string // "DOMAIN\\admin" o "user@domain.tld"
	Password string
	Domain   string // opcional, si no viene en Username
}

// HostInfo — info recopilada de un host Windows
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

// Collect ejecuta PowerShell remoto vía WinRM (requiere credenciales)
// para recopilar la info. Si la conexión falla, devuelve error.
func Collect(ctx context.Context, ip string, creds Creds, timeout time.Duration) (*HostInfo, error) {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// PowerShell script que junta todo lo que necesitamos como JSON
	script := `
$ErrorActionPreference = "SilentlyContinue"
$cs   = Get-CimInstance -ClassName Win32_ComputerSystem
$os   = Get-CimInstance -ClassName Win32_OperatingSystem
$bios = Get-CimInstance -ClassName Win32_BIOS
$cpu  = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | Measure-Object -Property Size -Sum
$swReg = @()
$paths = @(
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
foreach ($p in $paths) {
  $swReg += Get-ItemProperty $p -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Select-Object @{N="Name";E={$_.DisplayName}},
                  @{N="Version";E={$_.DisplayVersion}},
                  @{N="Publisher";E={$_.Publisher}},
                  @{N="InstallDate";E={$_.InstallDate}}
}
$out = @{
  hostname     = $cs.Name
  manufacturer = $cs.Manufacturer
  model        = $cs.Model
  os_name      = $os.Caption
  os_version   = $os.Version
  os_arch      = $os.OSArchitecture
  serial       = $bios.SerialNumber
  cpu_model    = $cpu.Name
  cpu_cores    = $cpu.NumberOfCores
  ram_gb       = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
  disk_gb      = [math]::Round($disk.Sum / 1GB, 1)
  software     = $swReg | Select-Object -First 200
}
$out | ConvertTo-Json -Compress -Depth 4
`
	// Vía Invoke-Command con credentials remotas
	psCmd := fmt.Sprintf(`
$pwd = ConvertTo-SecureString '%s' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('%s', $pwd)
Invoke-Command -ComputerName %s -Credential $cred -ScriptBlock { %s }
`, escapePowerShell(creds.Password), escapePowerShell(usernameWithDomain(creds)), ip, script)

	cmd := exec.CommandContext(ctx2, "powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell wmi %s: %w", ip, err)
	}

	var raw struct {
		Hostname     string  `json:"hostname"`
		Manufacturer string  `json:"manufacturer"`
		Model        string  `json:"model"`
		OSName       string  `json:"os_name"`
		OSVersion    string  `json:"os_version"`
		OSArch       string  `json:"os_arch"`
		Serial       string  `json:"serial"`
		CPUModel     string  `json:"cpu_model"`
		CPUCores     int     `json:"cpu_cores"`
		RAMGb        float64 `json:"ram_gb"`
		DiskGb       float64 `json:"disk_gb"`
		Software     []struct {
			Name        string `json:"Name"`
			Version     string `json:"Version"`
			Publisher   string `json:"Publisher"`
			InstallDate string `json:"InstallDate"`
		} `json:"software"`
	}
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("parse wmi json: %w", err)
	}

	info := &HostInfo{
		IP:           ip,
		Hostname:     raw.Hostname,
		Manufacturer: raw.Manufacturer,
		Model:        raw.Model,
		OSName:       raw.OSName,
		OSVersion:    raw.OSVersion,
		OSArch:       raw.OSArch,
		Serial:       raw.Serial,
		CPUModel:     raw.CPUModel,
		CPUCores:     raw.CPUCores,
		RAMGb:        raw.RAMGb,
		DiskGb:       raw.DiskGb,
	}
	for _, sw := range raw.Software {
		info.Software = append(info.Software, SoftwarePackage{
			Name:        sw.Name,
			Version:     sw.Version,
			Publisher:   sw.Publisher,
			InstallDate: sw.InstallDate,
		})
	}
	return info, nil
}

func escapePowerShell(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func usernameWithDomain(c Creds) string {
	if strings.Contains(c.Username, "\\") || strings.Contains(c.Username, "@") {
		return c.Username
	}
	if c.Domain != "" {
		return c.Domain + "\\" + c.Username
	}
	return c.Username
}
