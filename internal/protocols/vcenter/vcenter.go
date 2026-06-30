// Package vcenter enumera VMs + hosts ESXi de un vCenter Server vía la
// API SOAP de vSphere (govmomi).
package vcenter

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/vim25/mo"
)

// Creds — auth contra vCenter
type Creds struct {
	ServerURL string // https://vcenter.empresa.local
	Username  string // administrator@vsphere.local
	Password  string
	Insecure  bool   // skip TLS verify
}

// VM — info de una máquina virtual
type VM struct {
	Name         string
	UUID         string
	GuestOS      string
	PowerState   string
	NumCPU       int
	MemoryMB     int32
	IP           string
	HostName     string  // hostname del ESXi que la corre
	Hardware     string  // modelo del host
}

// Host — info de un host ESXi
type Host struct {
	Name         string
	Model        string
	Manufacturer string
	CPUModel     string
	CPUCores     int
	MemoryGB     float64
	Version      string
}

// Inventory contiene VMs + Hosts encontrados
type Inventory struct {
	VMs   []VM
	Hosts []Host
}

// Connect autentica + lista VMs y hosts
func Connect(ctx context.Context, creds Creds, timeout time.Duration) (*Inventory, error) {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rawURL := strings.TrimRight(creds.ServerURL, "/") + "/sdk"
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse vcenter url: %w", err)
	}
	u.User = url.UserPassword(creds.Username, creds.Password)

	client, err := govmomi.NewClient(ctx2, u, creds.Insecure)
	if err != nil {
		return nil, fmt.Errorf("govmomi connect: %w", err)
	}
	defer client.Logout(ctx2)

	// Forzar config TLS si insecure (govmomi acepta el flag pero a veces
	// re-usa el http.Transport default)
	if creds.Insecure {
		client.DefaultTransport().TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	finder := find.NewFinder(client.Client, true)
	inv := &Inventory{}

	// VMs
	vmRefs, err := finder.VirtualMachineList(ctx2, "*")
	if err == nil {
		for _, vmRef := range vmRefs {
			var vmo mo.VirtualMachine
			if err := vmRef.Properties(ctx2, vmRef.Reference(), []string{"summary", "config", "runtime"}, &vmo); err != nil {
				continue
			}
			vm := VM{
				Name:       vmo.Summary.Config.Name,
				UUID:       vmo.Summary.Config.Uuid,
				GuestOS:    vmo.Summary.Config.GuestFullName,
				PowerState: string(vmo.Runtime.PowerState),
				NumCPU:     int(vmo.Summary.Config.NumCpu),
				MemoryMB:   vmo.Summary.Config.MemorySizeMB,
				IP:         vmo.Summary.Guest.IpAddress,
			}
			inv.VMs = append(inv.VMs, vm)
		}
	}

	// Hosts ESXi
	hostRefs, err := finder.HostSystemList(ctx2, "*")
	if err == nil {
		for _, hostRef := range hostRefs {
			var ho mo.HostSystem
			if err := hostRef.Properties(ctx2, hostRef.Reference(), []string{"summary", "hardware", "config"}, &ho); err != nil {
				continue
			}
			h := Host{
				Name:    ho.Summary.Config.Name,
				Version: ho.Summary.Config.Product.FullName,
			}
			if ho.Hardware != nil {
				h.Model = ho.Hardware.SystemInfo.Model
				h.Manufacturer = ho.Hardware.SystemInfo.Vendor
				if ho.Hardware.CpuInfo.NumCpuCores > 0 {
					h.CPUCores = int(ho.Hardware.CpuInfo.NumCpuCores)
				}
				if ho.Hardware.MemorySize > 0 {
					h.MemoryGB = float64(ho.Hardware.MemorySize) / 1024.0 / 1024.0 / 1024.0
				}
				if len(ho.Hardware.CpuPkg) > 0 {
					h.CPUModel = ho.Hardware.CpuPkg[0].Description
				}
			}
			inv.Hosts = append(inv.Hosts, h)
		}
	}

	return inv, nil
}
