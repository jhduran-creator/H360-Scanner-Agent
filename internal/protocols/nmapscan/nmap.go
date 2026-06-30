// Package nmapscan wrappa la librería Ullaakut/nmap (que a su vez wrappa
// el binario nmap del sistema). Requiere que `nmap` esté instalado en
// el host donde corre el agente.
//
// Para Linux: `apt install nmap` o `apk add nmap`.
// Para Windows: descargar de https://nmap.org/download.html.
// El Dockerfile del agente lo incluye.
package nmapscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	n "github.com/Ullaakut/nmap/v3"
)

// Result — info de un host descubierto por nmap
type Result struct {
	IP        string
	Hostname  string
	OS        string  // best-guess
	OSVersion string
	OSAccuracy int
	OpenPorts []int
	MAC       string
}

// Scan corre nmap sobre una lista de IPs específicas (no CIDR) con
// fingerprint OS + service version. Requiere root/admin (raw sockets);
// sin permisos cae a un scan menos detallado que igual obtiene puertos
// abiertos.
//
// IMPORTANTE: targets debe ser una lista de IPs YA confirmadas vivas
// (típicamente del sweep ICMP previo). Pasar un CIDR /24 a nmap con
// OS detection es lento (5-10 min) Y genera ruido (reporta 256 entries
// aunque solo 5-10 estén vivas). Mejor: ICMP sweep primero + nmap solo
// sobre las vivas.
func Scan(ctx context.Context, targets []string, timeout time.Duration) ([]Result, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	scanner, err := n.NewScanner(
		ctx2,
		n.WithTargets(targets...),  // lista explícita de IPs vivas
		n.WithOSDetection(),
		n.WithServiceInfo(),
		n.WithTimingTemplate(n.TimingAggressive),
		// Solo puertos comunes para acelerar (top 100 + algunos extras)
		n.WithPorts("21,22,23,25,53,80,110,135,139,143,161,389,443,445,465,587,631,636,993,995,1433,1521,1723,2049,3306,3389,5432,5900,5985,5986,8080,8443,9100"),
		// Skip host discovery — confiamos en que el caller pasó solo IPs vivas
		n.WithSkipHostDiscovery(),
	)
	if err != nil {
		return nil, fmt.Errorf("nmap new scanner: %w", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		// Errors típicos: nmap not installed, permission denied
		return nil, fmt.Errorf("nmap run: %w (warnings: %v)", err, warnings)
	}

	out := make([]Result, 0, len(result.Hosts))
	for _, h := range result.Hosts {
		if len(h.Addresses) == 0 {
			continue
		}
		// Filtrar hosts down — nmap reporta TODOS los del rango aunque no
		// respondieran. Solo nos interesan los "up". Esto es la forma
		// correcta de filtrar ruido cuando el target es un CIDR.
		if h.Status.State != "up" {
			continue
		}
		r := Result{}
		// Tomamos la primera address IPv4
		for _, addr := range h.Addresses {
			if addr.AddrType == "ipv4" && r.IP == "" {
				r.IP = addr.Addr
			}
			if addr.AddrType == "mac" && r.MAC == "" {
				r.MAC = addr.Addr
			}
		}
		// Hostname del scan
		for _, hn := range h.Hostnames {
			if hn.Name != "" {
				r.Hostname = hn.Name
				break
			}
		}
		// OS detection con nmap es POCO CONFIABLE para clientes LAN típicos
		// (Mac, smartphone, IoT, router consumer) — nmap reporta "Aggressive
		// guesses" con accuracy 85% que son falsos (ej: "Allied Telesyn
		// AT-AR410 router" para una Mac).
		//
		// Estrategia conservadora:
		//   1. Threshold 95%+ → solo exact matches reales, NO guesses.
		//   2. Reportar OS Class (Family + Generation) que es info más útil:
		//        "Linux 4.x" en lugar de modelo específico falso
		//        "Windows 10" en lugar de versión exacta dudosa
		//   3. Si nmap no logra match con 95%+, OS=null. Más honesto.
		//      Para info confiable, usar SNMP/SSH/WMI/vCenter con credentials.
		const minOSAccuracy = 95
		if len(h.OS.Matches) > 0 {
			best := h.OS.Matches[0]
			r.OSAccuracy = best.Accuracy
			if best.Accuracy >= minOSAccuracy {
				// Preferimos Class (Family/Generation) sobre Name específico
				if len(best.Classes) > 0 {
					c := best.Classes[0]
					osClass := strings.TrimSpace(c.Family + " " + c.OSGeneration)
					if osClass != "" {
						r.OS = osClass
						r.OSVersion = c.OSGeneration
					}
				}
				// Solo fallback al Name específico si no había Class útil
				if r.OS == "" {
					r.OS = best.Name
				}
			}
			// Si accuracy < threshold, dejamos r.OS="" — más honesto que
			// reportar guess con baja confianza.
		}
		// Puertos abiertos
		for _, p := range h.Ports {
			if p.State.State == "open" {
				r.OpenPorts = append(r.OpenPorts, int(p.ID))
			}
		}
		// Filtrar ruido: nmap con -Pn devuelve un entry por cada IP del rango
		// aunque no haya respondido en ningún puerto. Solo reportar hosts con
		// info real (al menos 1 puerto abierto, OS detectado, MAC, o hostname).
		if len(r.OpenPorts) == 0 && r.OS == "" && r.MAC == "" && r.Hostname == "" {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
