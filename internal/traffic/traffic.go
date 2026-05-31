package traffic

import (
	"encoding/binary"
	"math/rand/v2"
	"net"

	"avoip-load-generator/internal/netflowv9"
)

// Profile drives pseudo-realistic IT vs AV flow fields.
type Profile struct {
	AVRatio   float64 // 0..1 fraction of flows that look like AV media / control.
	TenantIdx int
	Risky     bool // whole batch / packet risk styling
}

var (
	loadItPorts = []uint16{53, 80, 443, 22, 123, 389, 636, 445, 3389, 587, 993}
	avPorts = []uint16{
		554, 8554, 5000, 5001, 5002, 5003, 5004,
		5956, 5960, 5961, 5962, 5968, 5970, 5980, 5990,
		8008, 8009, 8010, 8011,
		8700, 8702, 8708, 8710, 8711, 8800, 8810,
		9710, 9000, 9998, 1935, 6970, 6980,
	}
)

// FillRecord writes one NetFlow data record for tenantIdx (used for subnet layout).
func FillRecord(rec []byte, p Profile, rng *rand.Rand, uptimeMS uint32) {
	isAV := rng.Float64() < p.AVRatio
	if p.Risky {
		isAV = true
	}

	srcIP, dstIP := pickEndpoints(rng, p.TenantIdx, isAV, p.Risky)
	proto := uint8(17) // UDP-heavy for AVoIP lab realism
	if !isAV && !p.Risky && rng.Float64() < 0.35 {
		proto = 6 // some TCP IT flows
	}

	var srcPort, dstPort uint16
	if isAV {
		srcPort = avPorts[rng.IntN(len(avPorts))]
		dstPort = avPorts[rng.IntN(len(avPorts))]
		if rng.Float64() < 0.2 {
			dstPort = uint16(5000 + rng.IntN(5))
		}
	} else {
		srcPort = uint16(rng.IntN(32768) + 32768)
		dstPort = loadItPorts[rng.IntN(len(loadItPorts))]
	}

	if p.Risky {
		// Unusual high ports + multicast-heavy destinations already set; push volume.
		srcPort = uint16(40000 + rng.IntN(20000))
		if rng.Float64() < 0.5 {
			dstPort = uint16(5000 + rng.IntN(5))
		}
	}

	var bytes, pkts uint32
	var first, last uint32
	if p.Risky {
		bytes = uint32(rng.IntN(1<<28)) + (400 << 20) // large / bursty
		pkts = uint32(rng.IntN(200000)) + 50000
		span := uint32(rng.IntN(120_000))
		if uptimeMS > span {
			first = uptimeMS - span
		}
		last = uptimeMS
	} else if isAV {
		bytes = uint32(rng.IntN(8<<20)) + (64 << 10)
		pkts = uint32(rng.IntN(8000)) + 50
		span := uint32(rng.IntN(4000))
		if uptimeMS > span {
			first = uptimeMS - span
		}
		last = uptimeMS
	} else {
		bytes = uint32(rng.IntN(256<<10)) + 64
		pkts = uint32(rng.IntN(400)) + 1
		span := uint32(rng.IntN(600000))
		if uptimeMS > span {
			first = uptimeMS - span
		}
		last = uptimeMS
	}

	tos := uint8(0)
	tcpFlags := uint8(0)
	if proto == 6 {
		tcpFlags = 0x18 // ACK+PSH-ish pattern without being exact TCP parse
	}
	if isAV && rng.Float64() < 0.25 {
		tos = 0xb8 // EF-like
	}

	netflowv9.WriteRecordFields(rec, bytes, pkts, proto, tos, tcpFlags, srcPort, dstPort, srcIP, dstIP, first, last)
}

func pickEndpoints(rng *rand.Rand, tenantIdx int, isAV, risky bool) (src, dst uint32) {
	// Tenant-scoped private space: 10.(100+tenant%120).x.y
	tOct := byte(100 + (tenantIdx % 120))
	srcHost := byte(2 + rng.IntN(250))
	src = ipv4(10, tOct, byte(rng.IntN(200)+1), srcHost)

	if risky && rng.Float64() < 0.45 {
		// "New" foreign endpoint — still private, but different macro block.
		src = ipv4(172, 16, byte(rng.IntN(200)+1), byte(2+rng.IntN(250)))
	}

	switch {
	case risky && rng.Float64() < 0.55:
		dst = ipv4(239, byte(rng.IntN(200)+1), byte(rng.IntN(200)+1), byte(rng.IntN(200)+1))
	case isAV && rng.Float64() < 0.35:
		// Multicast / control-plane style destinations
		if rng.Float64() < 0.5 {
			dst = ipv4(239, 255, byte(rng.IntN(50)), byte(rng.IntN(250)+1))
		} else {
			dst = ipv4(224, 0, byte(rng.IntN(30)+1), byte(rng.IntN(250)+1))
		}
	case isAV:
		dstHost := byte(2 + rng.IntN(250))
		dst = ipv4(10, tOct, byte(rng.IntN(200)+200), dstHost)
	default:
		dst = ipv4(10, tOct, 1, byte([]byte{2, 3, 4, 5, 10, 11}[rng.IntN(6)]))
	}
	return src, dst
}

func ipv4(a, b, c, d byte) uint32 {
	ip := net.IPv4(a, b, c, d)
	return binary.BigEndian.Uint32(ip.To4())
}
