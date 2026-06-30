// Package types contiene las estructuras compartidas entre el agente y
// el cloud. Mantener sincronizadas con backend/src/modules/scanners/dto/.
package types

import "time"

// HeartbeatReq — POST /scanner-inbound/heartbeat
type HeartbeatReq struct {
	AgentVersion string `json:"agent_version,omitempty"`
	AgentOS      string `json:"agent_os,omitempty"`
	Status       string `json:"status,omitempty"`
}

// HeartbeatResp — cloud responde con la config actual del scanner
type HeartbeatResp struct {
	Config ScannerConfig `json:"config"`
}

// ScannerConfig — lo que el cloud envía al agente para configurarlo
type ScannerConfig struct {
	Ranges           []ScanRange `json:"ranges,omitempty"`
	Schedule         string      `json:"schedule,omitempty"` // "every_5_min" | "hourly" | "daily" | "manual"
	EnabledProtocols []string    `json:"enabled_protocols,omitempty"`
}

type ScanRange struct {
	CIDR      string   `json:"cidr"`
	Label     string   `json:"label,omitempty"`
	Protocols []string `json:"protocols,omitempty"` // override de EnabledProtocols por rango
}

// CredentialsResp — GET /scanner-inbound/credentials
type CredentialsResp struct {
	Credentials []Credential `json:"credentials"`
}

type Credential struct {
	ID               string                 `json:"id"`
	Protocol         string                 `json:"protocol"` // snmp_v2c | snmp_v3 | wmi | ssh | ldap | vcenter
	Name             string                 `json:"name"`
	Data             map[string]interface{} `json:"data"` // plain — recibido vía HTTPS+HMAC
	AppliesToRanges  []string               `json:"applies_to_ranges,omitempty"`
}

// DiscoveryReportReq — POST /scanner-inbound/discovery-report
type DiscoveryReportReq struct {
	RunID          string           `json:"run_id"`
	StartedAt      time.Time        `json:"started_at"`
	EndedAt        time.Time        `json:"ended_at"`
	RangesScanned  []string         `json:"ranges_scanned"`
	Hosts          []DiscoveredHost `json:"hosts"`
	Errors         []DiscoveryError `json:"errors,omitempty"`
}

// DiscoveryReportResp — respuesta del cloud
type DiscoveryReportResp struct {
	Accepted int      `json:"accepted"`
	Errors   []string `json:"errors,omitempty"`
}

type DiscoveredHost struct {
	IP               string              `json:"ip,omitempty"`
	MAC              string              `json:"mac,omitempty"`
	Hostname         string              `json:"hostname,omitempty"`
	FQDN             string              `json:"fqdn,omitempty"`
	DiscoveryMethods []string            `json:"discovery_methods,omitempty"`
	OS               *HostOS             `json:"os,omitempty"`
	Hardware         *HostHardware       `json:"hardware,omitempty"`
	ADInfo           map[string]any      `json:"ad_info,omitempty"`
	SNMPInfo         map[string]any      `json:"snmp_info,omitempty"`
	Software         []HostSoftware      `json:"software,omitempty"`
	OpenPorts        []int               `json:"open_ports,omitempty"`
}

type HostOS struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

type HostHardware struct {
	Manufacturer string  `json:"manufacturer,omitempty"`
	Model        string  `json:"model,omitempty"`
	Serial       string  `json:"serial,omitempty"`
	CPUModel     string  `json:"cpu_model,omitempty"`
	CPUCores     int     `json:"cpu_cores,omitempty"`
	RAMGb        float64 `json:"ram_gb,omitempty"`
	DiskGb       float64 `json:"disk_gb,omitempty"`
}

type HostSoftware struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"` // YYYY-MM-DD
}

type DiscoveryError struct {
	IP     string `json:"ip,omitempty"`
	Method string `json:"method,omitempty"`
	Error  string `json:"error"`
}
