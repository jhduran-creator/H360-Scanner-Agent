// Package icmp implementa el sweep ping de un rango CIDR.
//
// IMPORTANTE permisos: ICMP requiere raw sockets. En Linux/Mac correr
// como root o con cap_net_raw (setcap 'cap_net_raw=+ep' /usr/local/bin/hd360-scanner).
// En Windows correr como Administrator. Si no hay permisos, el sweep
// silenciosamente NO encuentra hosts.
package icmp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	pingl "github.com/go-ping/ping"
)

// Result — un host que respondió al ping
type Result struct {
	IP  string
	RTT time.Duration
}

// SweepOptions — config del sweep
type SweepOptions struct {
	Timeout    time.Duration // por host (default 2s)
	Parallel   int           // workers concurrentes (default 64)
	PacketCount int          // pings por host (default 1)
}

// Default options
func defaultOptions() SweepOptions {
	return SweepOptions{
		Timeout:     2 * time.Second,
		Parallel:    64,
		PacketCount: 1,
	}
}

// Sweep recorre todas las IPs de un CIDR con ping. Devuelve los que respondieron.
// Si el CIDR es /24 son ~250 hosts. Concurrencia limitada por Parallel.
func Sweep(ctx context.Context, cidr string, opts *SweepOptions) ([]Result, error) {
	if opts == nil {
		o := defaultOptions()
		opts = &o
	}
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Parallel == 0 {
		opts.Parallel = 64
	}
	if opts.PacketCount == 0 {
		opts.PacketCount = 1
	}

	ips, err := expandCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("expand cidr %s: %w", cidr, err)
	}

	results := make([]Result, 0, 16)
	resultsMu := sync.Mutex{}
	sem := make(chan struct{}, opts.Parallel)
	wg := sync.WaitGroup{}

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		ip := ip
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			rtt, ok := pingHost(ip, opts.Timeout, opts.PacketCount)
			if ok {
				resultsMu.Lock()
				results = append(results, Result{IP: ip, RTT: rtt})
				resultsMu.Unlock()
			}
		}()
	}
	wg.Wait()
	return results, nil
}

// pingHost dispara N pings, devuelve (RTT promedio, true) si al menos uno respondió
func pingHost(ip string, timeout time.Duration, count int) (time.Duration, bool) {
	pinger, err := pingl.NewPinger(ip)
	if err != nil {
		return 0, false
	}
	pinger.Count = count
	pinger.Timeout = timeout
	// SetPrivileged=true requiere raw sockets (Linux: cap_net_raw o root).
	// SetPrivileged=false usa unprivileged UDP ping (Linux >= 3.x con sysctl
	// net.ipv4.ping_group_range; Windows no soporta).
	pinger.SetPrivileged(true)

	if err := pinger.Run(); err != nil {
		// Si falla privileged, fallback a unprivileged (best-effort)
		pinger.SetPrivileged(false)
		if err := pinger.Run(); err != nil {
			return 0, false
		}
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv > 0 {
		return stats.AvgRtt, true
	}
	return 0, false
}

// expandCIDR convierte "10.0.0.0/24" en lista de IPs (excluyendo net/broadcast).
// Acepta también IPs sueltas (las trata como /32 automáticamente — más amigable
// si el admin tipea "192.168.1.5" en lugar de "192.168.1.5/32").
func expandCIDR(cidr string) ([]string, error) {
	// Si no contiene "/", asumir host único — append /32
	if !strings.Contains(cidr, "/") {
		if ip := net.ParseIP(cidr); ip != nil {
			cidr = cidr + "/32"
		}
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, 256)
	ip := ipnet.IP.Mask(ipnet.Mask)
	for ; ipnet.Contains(ip); incIP(ip) {
		out = append(out, ip.String())
	}

	// Para /31 y /32, devolvemos todas. Para /30 y mayores, excluimos
	// network address (primera) y broadcast (última) — práctica estándar.
	if len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

// incIP incrementa una IP IPv4 in-place
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			return
		}
	}
}
