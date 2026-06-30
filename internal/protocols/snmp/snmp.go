// Package snmp implementa SNMP v2c/v3 queries contra equipos de red
// (switches, routers, printers, UPS, cámaras IP).
//
// OIDs estándar usados:
//   1.3.6.1.2.1.1.1.0  sysDescr      (descripción del equipo)
//   1.3.6.1.2.1.1.2.0  sysObjectID   (identificador vendor)
//   1.3.6.1.2.1.1.5.0  sysName       (hostname)
//   1.3.6.1.2.1.1.4.0  sysContact    (contacto admin)
//   1.3.6.1.2.1.1.6.0  sysLocation
//   1.3.6.1.2.1.1.3.0  sysUpTime
package snmp

import (
	"context"
	"fmt"
	"strings"
	"time"

	g "github.com/gosnmp/gosnmp"
)

// V2cCreds — credenciales SNMPv2c
type V2cCreds struct {
	Community string
}

// V3Creds — credenciales SNMPv3
type V3Creds struct {
	Username       string
	SecurityLevel  string // noAuthNoPriv | authNoPriv | authPriv
	AuthProtocol   string // MD5 | SHA
	AuthPassword   string
	PrivProtocol   string // DES | AES
	PrivPassword   string
}

// Result — info que devuelve un query exitoso
type Result struct {
	IP          string
	SysDescr    string
	SysName     string
	SysContact  string
	SysLocation string
	SysObjectID string
	SysUpTime   string
	Vendor      string // inferido de sysDescr / sysObjectID
}

// QueryV2c hace un get básico de los OIDs sysX vía SNMPv2c
func QueryV2c(ctx context.Context, ip string, creds V2cCreds, timeout time.Duration) (*Result, error) {
	params := &g.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: creds.Community,
		Version:   g.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}
	return query(ctx, params)
}

// QueryV3 hace un get básico vía SNMPv3 con USM (User Security Model)
func QueryV3(ctx context.Context, ip string, creds V3Creds, timeout time.Duration) (*Result, error) {
	msgFlags := g.NoAuthNoPriv
	switch strings.ToLower(creds.SecurityLevel) {
	case "authnopriv":
		msgFlags = g.AuthNoPriv
	case "authpriv":
		msgFlags = g.AuthPriv
	}

	usm := &g.UsmSecurityParameters{
		UserName: creds.Username,
	}
	if msgFlags >= g.AuthNoPriv {
		switch strings.ToUpper(creds.AuthProtocol) {
		case "SHA":
			usm.AuthenticationProtocol = g.SHA
		default:
			usm.AuthenticationProtocol = g.MD5
		}
		usm.AuthenticationPassphrase = creds.AuthPassword
	}
	if msgFlags == g.AuthPriv {
		switch strings.ToUpper(creds.PrivProtocol) {
		case "AES":
			usm.PrivacyProtocol = g.AES
		default:
			usm.PrivacyProtocol = g.DES
		}
		usm.PrivacyPassphrase = creds.PrivPassword
	}

	params := &g.GoSNMP{
		Target:             ip,
		Port:               161,
		Version:            g.Version3,
		SecurityModel:      g.UserSecurityModel,
		MsgFlags:           msgFlags,
		SecurityParameters: usm,
		Timeout:            timeout,
		Retries:            1,
	}
	return query(ctx, params)
}

// query ejecuta el get de OIDs sysX y construye Result
func query(_ context.Context, params *g.GoSNMP) (*Result, error) {
	if err := params.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s: %w", params.Target, err)
	}
	defer params.Conn.Close()

	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.2.0", // sysObjectID
		"1.3.6.1.2.1.1.3.0", // sysUpTime
		"1.3.6.1.2.1.1.4.0", // sysContact
		"1.3.6.1.2.1.1.5.0", // sysName
		"1.3.6.1.2.1.1.6.0", // sysLocation
	}
	pkt, err := params.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("snmp get %s: %w", params.Target, err)
	}

	res := &Result{IP: params.Target}
	for _, v := range pkt.Variables {
		val := stringValue(v.Value)
		switch v.Name {
		case ".1.3.6.1.2.1.1.1.0":
			res.SysDescr = val
		case ".1.3.6.1.2.1.1.2.0":
			res.SysObjectID = val
		case ".1.3.6.1.2.1.1.3.0":
			res.SysUpTime = val
		case ".1.3.6.1.2.1.1.4.0":
			res.SysContact = val
		case ".1.3.6.1.2.1.1.5.0":
			res.SysName = val
		case ".1.3.6.1.2.1.1.6.0":
			res.SysLocation = val
		}
	}
	res.Vendor = guessVendor(res.SysDescr, res.SysObjectID)
	return res, nil
}

// stringValue convierte cualquier tipo SNMP a string razonable
func stringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// guessVendor heurísticamente determina vendor del sysDescr/sysObjectID
func guessVendor(sysDescr, sysObjectID string) string {
	d := strings.ToLower(sysDescr)
	switch {
	case strings.Contains(d, "cisco"):
		return "Cisco"
	case strings.Contains(d, "juniper"):
		return "Juniper"
	case strings.Contains(d, "mikrotik"), strings.Contains(d, "routeros"):
		return "MikroTik"
	case strings.Contains(d, "hp "), strings.Contains(d, "hewlett"):
		return "HP"
	case strings.Contains(d, "dell"):
		return "Dell"
	case strings.Contains(d, "fortinet"):
		return "Fortinet"
	case strings.Contains(d, "palo alto"):
		return "Palo Alto"
	case strings.Contains(d, "ubiquiti"):
		return "Ubiquiti"
	case strings.Contains(d, "aruba"):
		return "Aruba"
	}
	// Por sysObjectID enterprise prefix
	// 1.3.6.1.4.1.9 → Cisco, 1.3.6.1.4.1.2636 → Juniper, etc.
	if strings.HasPrefix(sysObjectID, ".1.3.6.1.4.1.9.") {
		return "Cisco"
	}
	return ""
}
