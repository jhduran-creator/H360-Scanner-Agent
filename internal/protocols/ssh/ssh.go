// Package ssh ejecuta comandos remotos vía SSH sobre Linux/Unix targets
// para recopilar info de hardware/OS/software instalado.
package ssh

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	g "golang.org/x/crypto/ssh"
)

// Creds — autenticación SSH (password O private key)
type Creds struct {
	Username       string
	Password       string // si no hay PrivateKeyPEM
	PrivateKeyPEM  string // prevalece sobre Password si está presente
	Passphrase     string // opcional para PrivateKey encriptada
}

// HostInfo — info recopilada de un host Linux/Unix
type HostInfo struct {
	IP            string
	Hostname      string
	OSName        string
	OSVersion     string
	OSArch        string
	CPUModel      string
	CPUCores      int
	RAMGb         float64
	DiskGb        float64
	Software      []SoftwarePackage
}

type SoftwarePackage struct {
	Name    string
	Version string
}

// Collect conecta por SSH y ejecuta varios comandos para popular HostInfo.
// Tolerante a comandos que fallan (devuelve lo que pudo obtener).
func Collect(ip string, creds Creds, timeout time.Duration) (*HostInfo, error) {
	config, err := buildClientConfig(creds, timeout)
	if err != nil {
		return nil, err
	}

	client, err := g.Dial("tcp", ip+":22", config)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", ip, err)
	}
	defer client.Close()

	info := &HostInfo{IP: ip}

	// uname -a → hostname + os name + arch
	if out, err := run(client, "uname -snrm"); err == nil {
		fields := strings.Fields(out)
		if len(fields) >= 4 {
			info.OSName = fields[0]   // Linux | Darwin | FreeBSD
			info.Hostname = fields[1]
			info.OSVersion = fields[2] // kernel release
			info.OSArch = fields[3]
		}
	}

	// /proc/cpuinfo (Linux only) — modelo + cores
	if out, err := run(client, "grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2"); err == nil {
		info.CPUModel = strings.TrimSpace(out)
	}
	if out, err := run(client, "nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null"); err == nil {
		var n int
		fmt.Sscanf(strings.TrimSpace(out), "%d", &n)
		info.CPUCores = n
	}

	// RAM en GB (Linux: /proc/meminfo; Mac: sysctl)
	if out, err := run(client, "grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}'"); err == nil {
		var kb int64
		fmt.Sscanf(strings.TrimSpace(out), "%d", &kb)
		if kb > 0 {
			info.RAMGb = float64(kb) / 1024.0 / 1024.0
		}
	}

	// Disco total (raíz) en GB
	if out, err := run(client, "df -BG / 2>/dev/null | awk 'NR==2 {gsub(\"G\", \"\", $2); print $2}'"); err == nil {
		var gb float64
		fmt.Sscanf(strings.TrimSpace(out), "%f", &gb)
		info.DiskGb = gb
	}

	// Software: apt en Debian/Ubuntu, rpm en RHEL/CentOS
	if out, err := run(client, "command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Package}|${Version}\\n' 2>/dev/null | head -200"); err == nil && strings.TrimSpace(out) != "" {
		info.Software = parseSoftware(out, "|")
	} else if out, err := run(client, "command -v rpm >/dev/null 2>&1 && rpm -qa --queryformat '%{NAME}|%{VERSION}\\n' 2>/dev/null | head -200"); err == nil {
		info.Software = parseSoftware(out, "|")
	}

	return info, nil
}

// buildClientConfig prepara la ssh.ClientConfig con la auth correcta
func buildClientConfig(creds Creds, timeout time.Duration) (*g.ClientConfig, error) {
	var auth []g.AuthMethod
	if creds.PrivateKeyPEM != "" {
		var signer g.Signer
		var err error
		if creds.Passphrase != "" {
			signer, err = g.ParsePrivateKeyWithPassphrase([]byte(creds.PrivateKeyPEM), []byte(creds.Passphrase))
		} else {
			signer, err = g.ParsePrivateKey([]byte(creds.PrivateKeyPEM))
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		auth = append(auth, g.PublicKeys(signer))
	}
	if creds.Password != "" {
		auth = append(auth, g.Password(creds.Password))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("no auth methods provided")
	}

	return &g.ClientConfig{
		User:            creds.Username,
		Auth:            auth,
		HostKeyCallback: g.InsecureIgnoreHostKey(), // TODO: opcional known_hosts file
		Timeout:         timeout,
	}, nil
}

// run ejecuta un comando vía nueva session, devuelve stdout
func run(client *g.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var stdout bytes.Buffer
	sess.Stdout = &stdout
	if err := sess.Run(cmd); err != nil {
		return "", err
	}
	return stdout.String(), nil
}

// parseSoftware convierte "name|version\nname|version\n" → []SoftwarePackage
func parseSoftware(out, sep string) []SoftwarePackage {
	var list []SoftwarePackage
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		parts := strings.SplitN(line, sep, 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		list = append(list, SoftwarePackage{
			Name:    strings.TrimSpace(parts[0]),
			Version: strings.TrimSpace(parts[1]),
		})
	}
	return list
}
