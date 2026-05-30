package tenant

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Tenant describes one simulated exporter / observation domain.
type Tenant struct {
	ID         string
	ExporterIP net.IP
	// SourceID is NetFlow v9 header SourceId (goflow2 observation domain key).
	SourceID uint32
}

type yamlFile struct {
	Tenants []struct {
		ID         string `yaml:"id"`
		ExporterIP string `yaml:"exporter_ip"`
	} `yaml:"tenants"`
}

// LoadFile reads optional YAML with explicit tenant ids and exporter IPs.
func LoadFile(path string) ([]Tenant, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var y yamlFile
	if err := yaml.Unmarshal(b, &y); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	out := make([]Tenant, 0, len(y.Tenants))
	for i, row := range y.Tenants {
		ip := net.ParseIP(strings.TrimSpace(row.ExporterIP))
		if ip == nil {
			return nil, fmt.Errorf("tenant %d: bad exporter_ip %q", i, row.ExporterIP)
		}
		ip = ip.To4()
		if ip == nil {
			return nil, fmt.Errorf("tenant %d: need IPv4 exporter_ip", i)
		}
		id := strings.TrimSpace(row.ID)
		if id == "" {
			id = fmt.Sprintf("tenant-%d", i)
		}
		out = append(out, Tenant{
			ID:         id,
			ExporterIP: ip,
			SourceID:   sourceIDFor(i, id),
		})
	}
	return out, nil
}

func sourceIDFor(index int, id string) uint32 {
	// Stable, non-zero observation domain ids (template scope in goflow2).
	h := uint32(2166136261)
	for _, c := range id {
		h ^= uint32(c)
		h *= 16777619
	}
	if h < 256 {
		h += uint32(index) + 1024
	}
	return h
}

// BuildSynthetic fills up to want tenants using base IP and incrementing the
// last octet, then carrying into the third octet when the fourth wraps.
func BuildSynthetic(want int, base net.IP, existing []Tenant) []Tenant {
	base = base.To4()
	if base == nil {
		base = net.IPv4(192, 168, 100, 1)
	}
	out := append([]Tenant(nil), existing...)
	var ip net.IP
	if len(existing) > 0 {
		ip = cloneIP(existing[len(existing)-1].ExporterIP)
		bumpExporterIP(ip)
	} else {
		ip = cloneIP(base)
	}
	for len(out) < want {
		i := len(out)
		tid := fmt.Sprintf("synthetic-%d", i)
		out = append(out, Tenant{
			ID:         tid,
			ExporterIP: cloneIP(ip),
			SourceID:   sourceIDFor(i, tid),
		})
		bumpExporterIP(ip)
	}
	return out
}

func cloneIP(ip net.IP) net.IP {
	v := ip.To4()
	c := make(net.IP, 4)
	copy(c, v)
	return c
}

func bumpExporterIP(ip net.IP) {
	if len(ip) < 4 {
		return
	}
	if ip[3] != 255 {
		ip[3]++
		return
	}
	ip[3] = 1
	if ip[2] != 255 {
		ip[2]++
		return
	}
	ip[2] = 0
	if ip[1] != 255 {
		ip[1]++
		return
	}
	ip[1] = 0
	ip[0]++
}

// ParseIPv4 parses dotted IPv4 or returns nil.
func ParseIPv4(s string) net.IP {
	return net.ParseIP(strings.TrimSpace(s)).To4()
}
