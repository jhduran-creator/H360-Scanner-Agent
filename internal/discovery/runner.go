// Package discovery orquesta la ejecución de los protocolos sobre los
// rangos configurados + arma el payload para mandar al cloud.
//
// Estrategia: ICMP primero (rápido, sin auth, identifica IPs vivas),
// después protocolos con credentials sobre cada IP viva (SNMP/WMI/SSH/vCenter).
// LDAP es aparte: enumera computer objects de AD independientemente del scan IP.
// nmap se corre como segundo barrido sobre los rangos para fingerprint OS+puertos.
package discovery

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kuanta-bridge/hd360-scanner/internal/protocols/icmp"
	"github.com/kuanta-bridge/hd360-scanner/internal/protocols/ldap"
	"github.com/kuanta-bridge/hd360-scanner/internal/protocols/nmapscan"
	"github.com/kuanta-bridge/hd360-scanner/internal/protocols/snmp"
	"github.com/kuanta-bridge/hd360-scanner/internal/protocols/ssh"
	"github.com/kuanta-bridge/hd360-scanner/internal/protocols/vcenter"
	"github.com/kuanta-bridge/hd360-scanner/internal/protocols/wmi"
	"github.com/kuanta-bridge/hd360-scanner/internal/types"
)

// Runner — ejecuta un discovery run completo según config
type Runner struct {
	log *slog.Logger
}

func NewRunner(log *slog.Logger) *Runner {
	return &Runner{log: log}
}

// Run ejecuta un scan completo según config + credentials recibidos del cloud.
func (r *Runner) Run(ctx context.Context, cfg types.ScannerConfig, credentials []types.Credential) types.DiscoveryReportReq {
	runID := uuid.New().String()
	startedAt := time.Now()
	r.log.Info("discovery run iniciado", "run_id", runID, "ranges", len(cfg.Ranges))

	hostsByIP := make(map[string]*types.DiscoveredHost)
	hostsMu := sync.Mutex{}
	var errors []types.DiscoveryError
	errorsMu := sync.Mutex{}
	rangesScanned := make([]string, 0, len(cfg.Ranges))

	appendError := func(e types.DiscoveryError) {
		errorsMu.Lock()
		errors = append(errors, e)
		errorsMu.Unlock()
	}

	upsertHost := func(ip string, mutate func(*types.DiscoveredHost)) {
		hostsMu.Lock()
		defer hostsMu.Unlock()
		h, ok := hostsByIP[ip]
		if !ok {
			h = &types.DiscoveredHost{IP: ip, DiscoveryMethods: []string{}}
			hostsByIP[ip] = h
		}
		mutate(h)
	}

	// ── Paso 1: LDAP (si configurado) — enumera computers del AD ────
	if isEnabled(cfg.EnabledProtocols, "ldap") {
		for _, cred := range credsForProtocol(credentials, "ldap") {
			if err := r.scanLDAP(cred, upsertHost, appendError); err != nil {
				r.log.Warn("LDAP falló", "cred", cred.Name, "err", err)
			}
		}
	}

	// ── Paso 2: por cada rango, ICMP sweep + (opcional) nmap + queries ──
	for _, rng := range cfg.Ranges {
		select {
		case <-ctx.Done():
			r.log.Warn("discovery cancelado por contexto", "run_id", runID)
			break
		default:
		}
		rangesScanned = append(rangesScanned, rng.CIDR)
		protos := rng.Protocols
		if len(protos) == 0 {
			protos = cfg.EnabledProtocols
		}

		// 2a. ICMP sweep
		var aliveIPs []string
		if isEnabled(protos, "icmp") {
			ips := r.scanICMP(ctx, rng.CIDR, upsertHost, appendError)
			aliveIPs = ips
		}

		// 2b. nmap fingerprint sobre los hosts vivos del ICMP (NO el CIDR
		// completo — eso reporta 256 entries en un /24 aunque solo haya
		// 8 vivas). Pasamos lista explícita de IPs para eficiencia + 0 ruido.
		if isEnabled(protos, "nmap") && len(aliveIPs) > 0 {
			r.scanNmap(ctx, aliveIPs, upsertHost, appendError)
		}

		// 2c. SNMP v2c/v3 sobre IPs vivas
		if isEnabled(protos, "snmp_v2c") {
			for _, cred := range credsForProtocol(credentials, "snmp_v2c") {
				if !appliesToRange(cred, rng.CIDR) {
					continue
				}
				for _, ip := range aliveIPs {
					r.scanSNMPv2c(ctx, ip, cred, upsertHost, appendError)
				}
			}
		}
		if isEnabled(protos, "snmp_v3") {
			for _, cred := range credsForProtocol(credentials, "snmp_v3") {
				if !appliesToRange(cred, rng.CIDR) {
					continue
				}
				for _, ip := range aliveIPs {
					r.scanSNMPv3(ctx, ip, cred, upsertHost, appendError)
				}
			}
		}

		// 2d. WMI sobre IPs vivas (solo Windows agent funciona realmente)
		if isEnabled(protos, "wmi") {
			for _, cred := range credsForProtocol(credentials, "wmi") {
				if !appliesToRange(cred, rng.CIDR) {
					continue
				}
				for _, ip := range aliveIPs {
					r.scanWMI(ctx, ip, cred, upsertHost, appendError)
				}
			}
		}

		// 2e. SSH sobre IPs vivas
		if isEnabled(protos, "ssh") {
			for _, cred := range credsForProtocol(credentials, "ssh") {
				if !appliesToRange(cred, rng.CIDR) {
					continue
				}
				for _, ip := range aliveIPs {
					r.scanSSH(ip, cred, upsertHost, appendError)
				}
			}
		}
	}

	// ── Paso 3: vCenter (independiente de rangos — se conecta a una API) ──
	if isEnabled(cfg.EnabledProtocols, "vcenter") {
		for _, cred := range credsForProtocol(credentials, "vcenter") {
			r.scanVCenter(ctx, cred, upsertHost, appendError)
		}
	}

	// Materializar mapa → slice
	hosts := make([]types.DiscoveredHost, 0, len(hostsByIP))
	for _, h := range hostsByIP {
		hosts = append(hosts, *h)
	}

	endedAt := time.Now()
	r.log.Info("discovery run completado",
		"run_id", runID,
		"duration", endedAt.Sub(startedAt),
		"hosts", len(hosts),
		"errors", len(errors),
	)

	return types.DiscoveryReportReq{
		RunID:         runID,
		StartedAt:     startedAt,
		EndedAt:       endedAt,
		RangesScanned: rangesScanned,
		Hosts:         hosts,
		Errors:        errors,
	}
}

// ── Wrappers por protocolo ───────────────────────────────────────────────

func (r *Runner) scanICMP(ctx context.Context, cidr string, upsert func(string, func(*types.DiscoveredHost)), errFn func(types.DiscoveryError)) []string {
	r.log.Debug("ICMP sweep iniciado", "cidr", cidr)
	results, err := icmp.Sweep(ctx, cidr, nil)
	if err != nil {
		r.log.Warn("ICMP sweep falló", "cidr", cidr, "err", err)
		errFn(types.DiscoveryError{Method: "icmp", Error: err.Error()})
		return nil
	}
	ips := make([]string, 0, len(results))
	for _, res := range results {
		upsert(res.IP, func(h *types.DiscoveredHost) {
			addMethod(h, "icmp")
		})
		ips = append(ips, res.IP)
	}
	r.log.Info("ICMP sweep completado", "cidr", cidr, "alive", len(ips))
	return ips
}

func (r *Runner) scanNmap(ctx context.Context, targets []string, upsert func(string, func(*types.DiscoveredHost)), errFn func(types.DiscoveryError)) {
	r.log.Debug("nmap scan iniciado", "targets", len(targets))
	results, err := nmapscan.Scan(ctx, targets, 10*time.Minute)
	if err != nil {
		r.log.Warn("nmap scan falló", "err", err)
		errFn(types.DiscoveryError{Method: "nmap", Error: err.Error()})
		return
	}
	for _, res := range results {
		upsert(res.IP, func(h *types.DiscoveredHost) {
			addMethod(h, "nmap")
			if res.MAC != "" && h.MAC == "" {
				h.MAC = res.MAC
			}
			if res.Hostname != "" && h.Hostname == "" {
				h.Hostname = res.Hostname
			}
			if res.OS != "" {
				if h.OS == nil {
					h.OS = &types.HostOS{}
				}
				if h.OS.Name == "" {
					h.OS.Name = res.OS
				}
				if h.OS.Version == "" {
					h.OS.Version = res.OSVersion
				}
			}
			if len(res.OpenPorts) > 0 {
				h.OpenPorts = mergeIntSlices(h.OpenPorts, res.OpenPorts)
			}
		})
	}
	r.log.Info("nmap scan completado", "targets", len(targets), "hosts", len(results))
}

func (r *Runner) scanSNMPv2c(_ context.Context, ip string, cred types.Credential, upsert func(string, func(*types.DiscoveredHost)), errFn func(types.DiscoveryError)) {
	creds := snmp.V2cCreds{Community: stringField(cred.Data, "community")}
	res, err := snmp.QueryV2c(nil, ip, creds, 3*time.Second)
	if err != nil {
		// Silencioso para SNMP — la mayoría de IPs no responden y es OK
		return
	}
	upsert(ip, func(h *types.DiscoveredHost) {
		addMethod(h, "snmp_v2c")
		if res.SysName != "" && h.Hostname == "" {
			h.Hostname = res.SysName
		}
		if h.SNMPInfo == nil {
			h.SNMPInfo = map[string]any{}
		}
		h.SNMPInfo["sysDescr"] = res.SysDescr
		h.SNMPInfo["sysName"] = res.SysName
		h.SNMPInfo["sysContact"] = res.SysContact
		h.SNMPInfo["sysLocation"] = res.SysLocation
		h.SNMPInfo["sysObjectID"] = res.SysObjectID
		if res.Vendor != "" {
			if h.Hardware == nil {
				h.Hardware = &types.HostHardware{}
			}
			if h.Hardware.Manufacturer == "" {
				h.Hardware.Manufacturer = res.Vendor
			}
		}
	})
	_ = errFn
}

func (r *Runner) scanSNMPv3(_ context.Context, ip string, cred types.Credential, upsert func(string, func(*types.DiscoveredHost)), errFn func(types.DiscoveryError)) {
	creds := snmp.V3Creds{
		Username:      stringField(cred.Data, "username"),
		SecurityLevel: stringField(cred.Data, "security_level"),
		AuthProtocol:  stringField(cred.Data, "auth_protocol"),
		AuthPassword:  stringField(cred.Data, "auth_password"),
		PrivProtocol:  stringField(cred.Data, "priv_protocol"),
		PrivPassword:  stringField(cred.Data, "priv_password"),
	}
	res, err := snmp.QueryV3(nil, ip, creds, 3*time.Second)
	if err != nil {
		return
	}
	upsert(ip, func(h *types.DiscoveredHost) {
		addMethod(h, "snmp_v3")
		if res.SysName != "" && h.Hostname == "" {
			h.Hostname = res.SysName
		}
		if h.SNMPInfo == nil {
			h.SNMPInfo = map[string]any{}
		}
		h.SNMPInfo["sysDescr"] = res.SysDescr
		h.SNMPInfo["sysName"] = res.SysName
	})
	_ = errFn
}

func (r *Runner) scanWMI(ctx context.Context, ip string, cred types.Credential, upsert func(string, func(*types.DiscoveredHost)), errFn func(types.DiscoveryError)) {
	creds := wmi.Creds{
		Username: stringField(cred.Data, "username"),
		Password: stringField(cred.Data, "password"),
		Domain:   stringField(cred.Data, "domain"),
	}
	info, err := wmi.Collect(ctx, ip, creds, 60*time.Second)
	if err != nil {
		// Silencioso: la mayoría de IPs no responden WMI
		return
	}
	upsert(ip, func(h *types.DiscoveredHost) {
		addMethod(h, "wmi")
		if info.Hostname != "" && h.Hostname == "" {
			h.Hostname = info.Hostname
		}
		if h.OS == nil {
			h.OS = &types.HostOS{}
		}
		if info.OSName != "" {
			h.OS.Name = info.OSName
		}
		if info.OSVersion != "" {
			h.OS.Version = info.OSVersion
		}
		if info.OSArch != "" {
			h.OS.Arch = info.OSArch
		}
		if h.Hardware == nil {
			h.Hardware = &types.HostHardware{}
		}
		if info.Manufacturer != "" {
			h.Hardware.Manufacturer = info.Manufacturer
		}
		if info.Model != "" {
			h.Hardware.Model = info.Model
		}
		if info.Serial != "" {
			h.Hardware.Serial = info.Serial
		}
		if info.CPUModel != "" {
			h.Hardware.CPUModel = info.CPUModel
		}
		if info.CPUCores > 0 {
			h.Hardware.CPUCores = info.CPUCores
		}
		if info.RAMGb > 0 {
			h.Hardware.RAMGb = info.RAMGb
		}
		if info.DiskGb > 0 {
			h.Hardware.DiskGb = info.DiskGb
		}
		for _, sw := range info.Software {
			h.Software = append(h.Software, types.HostSoftware{
				Name:        sw.Name,
				Version:     sw.Version,
				Publisher:   sw.Publisher,
				InstallDate: sw.InstallDate,
			})
		}
	})
	_ = errFn
}

func (r *Runner) scanSSH(ip string, cred types.Credential, upsert func(string, func(*types.DiscoveredHost)), errFn func(types.DiscoveryError)) {
	creds := ssh.Creds{
		Username:      stringField(cred.Data, "username"),
		Password:      stringField(cred.Data, "password"),
		PrivateKeyPEM: stringField(cred.Data, "private_key_pem"),
		Passphrase:    stringField(cred.Data, "passphrase"),
	}
	info, err := ssh.Collect(ip, creds, 10*time.Second)
	if err != nil {
		// Silencioso
		return
	}
	upsert(ip, func(h *types.DiscoveredHost) {
		addMethod(h, "ssh")
		if info.Hostname != "" && h.Hostname == "" {
			h.Hostname = info.Hostname
		}
		if h.OS == nil {
			h.OS = &types.HostOS{}
		}
		if info.OSName != "" {
			h.OS.Name = info.OSName
		}
		if info.OSVersion != "" {
			h.OS.Version = info.OSVersion
		}
		if info.OSArch != "" {
			h.OS.Arch = info.OSArch
		}
		if h.Hardware == nil {
			h.Hardware = &types.HostHardware{}
		}
		if info.CPUModel != "" {
			h.Hardware.CPUModel = info.CPUModel
		}
		if info.CPUCores > 0 {
			h.Hardware.CPUCores = info.CPUCores
		}
		if info.RAMGb > 0 {
			h.Hardware.RAMGb = info.RAMGb
		}
		if info.DiskGb > 0 {
			h.Hardware.DiskGb = info.DiskGb
		}
		for _, sw := range info.Software {
			h.Software = append(h.Software, types.HostSoftware{
				Name:    sw.Name,
				Version: sw.Version,
			})
		}
	})
	_ = errFn
}

func (r *Runner) scanLDAP(cred types.Credential, upsert func(string, func(*types.DiscoveredHost)), errFn func(types.DiscoveryError)) error {
	creds := ldap.Creds{
		ServerURL:    stringField(cred.Data, "server_url"),
		BindDN:       stringField(cred.Data, "bind_dn"),
		BindPassword: stringField(cred.Data, "bind_password"),
		BaseDN:       stringField(cred.Data, "base_dn"),
	}
	comps, err := ldap.ListComputers(creds, 30*time.Second)
	if err != nil {
		errFn(types.DiscoveryError{Method: "ldap", Error: err.Error()})
		return err
	}
	r.log.Info("LDAP completado", "computers", len(comps))
	for _, c := range comps {
		// Sin IP — usamos el DNS hostname como key
		key := c.DNSHostname
		if key == "" {
			key = c.Name
		}
		if key == "" {
			continue
		}
		upsert(key, func(h *types.DiscoveredHost) {
			addMethod(h, "ldap")
			if c.DNSHostname != "" {
				h.FQDN = c.DNSHostname
			}
			if c.Name != "" && h.Hostname == "" {
				h.Hostname = c.Name
			}
			if h.OS == nil {
				h.OS = &types.HostOS{}
			}
			if c.OperatingSystem != "" && h.OS.Name == "" {
				h.OS.Name = c.OperatingSystem
			}
			if c.OSVersion != "" && h.OS.Version == "" {
				h.OS.Version = c.OSVersion
			}
			if h.ADInfo == nil {
				h.ADInfo = map[string]any{}
			}
			h.ADInfo["dn"] = c.DistinguishedName
			if !c.LastLogonTime.IsZero() {
				h.ADInfo["last_logon"] = c.LastLogonTime.Format(time.RFC3339)
			}
		})
	}
	return nil
}

func (r *Runner) scanVCenter(ctx context.Context, cred types.Credential, upsert func(string, func(*types.DiscoveredHost)), errFn func(types.DiscoveryError)) {
	creds := vcenter.Creds{
		ServerURL: stringField(cred.Data, "server_url"),
		Username:  stringField(cred.Data, "username"),
		Password:  stringField(cred.Data, "password"),
		Insecure:  boolField(cred.Data, "insecure"),
	}
	inv, err := vcenter.Connect(ctx, creds, 60*time.Second)
	if err != nil {
		errFn(types.DiscoveryError{Method: "vcenter", Error: err.Error()})
		return
	}
	r.log.Info("vCenter completado", "vms", len(inv.VMs), "hosts", len(inv.Hosts))

	// VMs como hosts independientes, key por IP si la tienen, fallback al UUID
	for _, vm := range inv.VMs {
		key := vm.IP
		if key == "" {
			key = "vm:" + vm.UUID
		}
		upsert(key, func(h *types.DiscoveredHost) {
			addMethod(h, "vcenter")
			if vm.IP != "" {
				h.IP = vm.IP
			}
			if vm.Name != "" && h.Hostname == "" {
				h.Hostname = vm.Name
			}
			if h.OS == nil {
				h.OS = &types.HostOS{}
			}
			if vm.GuestOS != "" && h.OS.Name == "" {
				h.OS.Name = vm.GuestOS
			}
			if h.Hardware == nil {
				h.Hardware = &types.HostHardware{}
			}
			if vm.NumCPU > 0 {
				h.Hardware.CPUCores = vm.NumCPU
			}
			if vm.MemoryMB > 0 {
				h.Hardware.RAMGb = float64(vm.MemoryMB) / 1024.0
			}
		})
	}
	// Hosts ESXi como entradas separadas
	for _, host := range inv.Hosts {
		key := "esxi:" + host.Name
		upsert(key, func(h *types.DiscoveredHost) {
			addMethod(h, "vcenter")
			if host.Name != "" {
				h.Hostname = host.Name
			}
			if h.Hardware == nil {
				h.Hardware = &types.HostHardware{}
			}
			h.Hardware.Manufacturer = host.Manufacturer
			h.Hardware.Model = host.Model
			h.Hardware.CPUModel = host.CPUModel
			h.Hardware.CPUCores = host.CPUCores
			h.Hardware.RAMGb = host.MemoryGB
			if h.OS == nil {
				h.OS = &types.HostOS{}
			}
			h.OS.Name = "VMware ESXi"
			h.OS.Version = host.Version
		})
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────

func isEnabled(protos []string, target string) bool {
	for _, p := range protos {
		if p == target {
			return true
		}
	}
	return false
}

func credsForProtocol(creds []types.Credential, protocol string) []types.Credential {
	var out []types.Credential
	for _, c := range creds {
		if c.Protocol == protocol {
			out = append(out, c)
		}
	}
	return out
}

// appliesToRange: si applies_to_ranges está vacío, aplica a todos.
// Si tiene CIDRs, devuelve true si el CIDR del rango está en la lista.
// Simplificación: comparación de string exacta (admin debe configurar
// con el mismo formato CIDR).
func appliesToRange(c types.Credential, cidr string) bool {
	if len(c.AppliesToRanges) == 0 {
		return true
	}
	for _, r := range c.AppliesToRanges {
		if strings.EqualFold(strings.TrimSpace(r), cidr) {
			return true
		}
	}
	return false
}

func addMethod(h *types.DiscoveredHost, m string) {
	for _, x := range h.DiscoveryMethods {
		if x == m {
			return
		}
	}
	h.DiscoveryMethods = append(h.DiscoveryMethods, m)
}

func mergeIntSlices(a, b []int) []int {
	seen := make(map[int]bool, len(a))
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			a = append(a, x)
			seen[x] = true
		}
	}
	return a
}

func stringField(m map[string]interface{}, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func boolField(m map[string]interface{}, k string) bool {
	if v, ok := m[k]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
