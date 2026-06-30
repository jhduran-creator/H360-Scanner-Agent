// Package ldap implementa enumeración de Computer objects de un dominio
// Active Directory vía LDAP. Útil para descubrir hosts del dominio
// incluso si están apagados en el momento del scan.
package ldap

import (
	"crypto/tls"
	"fmt"
	"time"

	l "github.com/go-ldap/ldap/v3"
)

// Creds — credenciales para bind LDAP
type Creds struct {
	ServerURL    string // ldap://dc.empresa.local:389 o ldaps://...:636
	BindDN       string // CN=user,OU=...,DC=...
	BindPassword string
	BaseDN       string // DC=empresa,DC=local
}

// Computer — un objeto computadora encontrado en AD
type Computer struct {
	Name              string
	DNSHostname       string
	OperatingSystem   string
	OSVersion         string
	DistinguishedName string
	Description       string
	LastLogonTime     time.Time
}

// ListComputers conecta + bind + search Computer objects bajo BaseDN
func ListComputers(creds Creds, timeout time.Duration) ([]Computer, error) {
	var conn *l.Conn
	var err error
	if isLdaps(creds.ServerURL) {
		conn, err = l.DialURL(creds.ServerURL, l.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: true, // lab — TODO: hacerlo configurable
		}))
	} else {
		conn, err = l.DialURL(creds.ServerURL)
	}
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(timeout)

	if err := conn.Bind(creds.BindDN, creds.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap bind: %w", err)
	}

	req := l.NewSearchRequest(
		creds.BaseDN,
		l.ScopeWholeSubtree,
		l.NeverDerefAliases,
		0,    // no size limit
		0,    // no time limit
		false,
		"(objectClass=computer)",
		[]string{"cn", "dNSHostName", "operatingSystem", "operatingSystemVersion", "description", "lastLogonTimestamp"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}

	out := make([]Computer, 0, len(res.Entries))
	for _, e := range res.Entries {
		c := Computer{
			Name:              e.GetAttributeValue("cn"),
			DNSHostname:       e.GetAttributeValue("dNSHostName"),
			OperatingSystem:   e.GetAttributeValue("operatingSystem"),
			OSVersion:         e.GetAttributeValue("operatingSystemVersion"),
			DistinguishedName: e.DN,
			Description:       e.GetAttributeValue("description"),
		}
		// lastLogonTimestamp es un Windows file time (100-ns intervals desde 1601)
		if ts := e.GetAttributeValue("lastLogonTimestamp"); ts != "" {
			c.LastLogonTime = parseWindowsFileTime(ts)
		}
		out = append(out, c)
	}
	return out, nil
}

// isLdaps detecta si la URL es ldaps://
func isLdaps(url string) bool {
	return len(url) >= 8 && url[:8] == "ldaps://"
}

// parseWindowsFileTime convierte un Windows file time (string en ldap) a time.Time
func parseWindowsFileTime(s string) time.Time {
	var v int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return time.Time{}
		}
		v = v*10 + int64(c-'0')
	}
	if v == 0 {
		return time.Time{}
	}
	// Windows epoch: 1601-01-01. Diferencia en segundos al Unix epoch.
	const windowsToUnixOffsetSec = 11644473600
	unixSec := v/10000000 - windowsToUnixOffsetSec
	return time.Unix(unixSec, 0).UTC()
}
