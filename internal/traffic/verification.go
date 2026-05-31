package traffic

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"

	"avoip-load-generator/internal/netflowv9"
)

// DeviceRole identifies a fixed lab endpoint type for behavioral verification.
type DeviceRole int

const (
	RoleDante DeviceRole = iota
	RoleNDI
	RoleST2110
	RoleEncoder
	RoleMDNS
	RoleHighBW
	RoleAVControl
	RoleIT
)

func (r DeviceRole) String() string {
	switch r {
	case RoleDante:
		return "dante"
	case RoleNDI:
		return "ndi"
	case RoleST2110:
		return "st2110"
	case RoleEncoder:
		return "encoder"
	case RoleMDNS:
		return "mdns"
	case RoleHighBW:
		return "highbw"
	case RoleAVControl:
		return "avcontrol"
	case RoleIT:
		return "it"
	default:
		return "unknown"
	}
}

// Endpoint is one stable device in the verification lab.
type Endpoint struct {
	IP   uint32
	Role DeviceRole
	Name string
}

// VerificationLab holds a fixed pool of internal endpoints for repeatable behavioral testing.
type VerificationLab struct {
	Endpoints []Endpoint
	byRole    map[DeviceRole][]int
	allowed   map[uint32]struct{}
}

var (
	publicDsts = []uint32{
		ipv4(8, 8, 8, 8),
		ipv4(93, 184, 216, 34),
		ipv4(142, 250, 190, 78),
		ipv4(3, 230, 185, 207),
	}
	itPorts = []uint16{53, 443, 80, 123}
)

type roleSpec struct {
	role       DeviceRole
	baseCount  int
	thirdOctet byte
	startHost  byte
	namePrefix string
}

// DefaultRoleCount is the minimum endpoint count (one device per role).
func DefaultRoleCount() int {
	return len(defaultRoleSpecs)
}

var defaultRoleSpecs = []roleSpec{
	{RoleDante, 8, 10, 11, "dante"},
	{RoleNDI, 8, 20, 21, "ndi"},
	{RoleST2110, 6, 30, 31, "st2110"},
	{RoleEncoder, 4, 40, 41, "encoder"},
	{RoleMDNS, 2, 0, 0, "mdns"}, // special layout
	{RoleHighBW, 6, 50, 51, "highbw"},
	{RoleAVControl, 4, 60, 61, "avcontrol"},
	{RoleIT, 12, 128, 101, "it"},
}

// NewVerificationLab builds a deterministic endpoint pool of n devices (default layout at n=50).
func NewVerificationLab(n int) *VerificationLab {
	if n < len(defaultRoleSpecs) {
		n = len(defaultRoleSpecs)
	}
	counts := scaleRoleCounts(n)
	lab := &VerificationLab{
		byRole:  make(map[DeviceRole][]int),
		allowed: make(map[uint32]struct{}),
	}
	idx := 0
	for _, spec := range defaultRoleSpecs {
		if spec.role == RoleIT {
			continue
		}
		c := counts[spec.role]
		for i := 0; i < c; i++ {
			ep := Endpoint{Role: spec.role}
			switch spec.role {
			case RoleMDNS:
				if i == 0 {
					ep.IP = ipv4(192, 168, 10, 50)
				} else if i == 1 {
					ep.IP = ipv4(192, 168, 20, 50)
				} else {
					ep.IP = ipv4(192, 168, 20, byte(50+i))
				}
			default:
				ep.IP = ipv4(192, 168, spec.thirdOctet, spec.startHost+byte(i))
			}
			ep.Name = fmt.Sprintf("%s-%02d", spec.namePrefix, i+1)
			lab.addEndpoint(ep, idx)
			idx++
		}
	}
	for i := 0; i < counts[RoleIT]; i++ {
		ep := Endpoint{
			IP:   ipv4(192, 168, 128, 101+byte(i)),
			Role: RoleIT,
			Name: fmt.Sprintf("it-%02d", i+1),
		}
		lab.addEndpoint(ep, idx)
		idx++
	}
	return lab
}

func (lab *VerificationLab) addEndpoint(ep Endpoint, idx int) {
	lab.Endpoints = append(lab.Endpoints, ep)
	lab.byRole[ep.Role] = append(lab.byRole[ep.Role], idx)
	lab.allowed[ep.IP] = struct{}{}
}

func scaleRoleCounts(n int) map[DeviceRole]int {
	const baseTotal = 50
	counts := make(map[DeviceRole]int)
	assigned := 0
	for _, spec := range defaultRoleSpecs {
		if spec.role == RoleIT {
			continue
		}
		c := n * spec.baseCount / baseTotal
		if c < 1 {
			c = 1
		}
		counts[spec.role] = c
		assigned += c
	}
	it := n - assigned
	if it < 1 {
		it = 1
	}
	counts[RoleIT] = it
	return counts
}

// RosterLines returns human-readable endpoint listings for startup output.
func (lab *VerificationLab) RosterLines() []string {
	lines := make([]string, len(lab.Endpoints))
	for i, ep := range lab.Endpoints {
		lines[i] = fmt.Sprintf("%s %s", IPString(ep.IP), ep.Name)
	}
	return lines
}

// AllowedDestinations returns lab IPs plus fixed multicast and public destinations used by flows.
func (lab *VerificationLab) AllowedDestinations() map[uint32]struct{} {
	out := make(map[uint32]struct{}, len(lab.allowed)+32)
	for ip := range lab.allowed {
		out[ip] = struct{}{}
	}
	for _, ep := range lab.Endpoints {
		host := parseHostOctet(ep.IP)
		switch ep.Role {
		case RoleDante:
			out[ipv4(239, 255, 0, host)] = struct{}{}
		case RoleST2110, RoleHighBW:
			out[ipv4(239, 69, 1, host)] = struct{}{}
			out[ipv4(239, 1, 2, host)] = struct{}{}
		}
	}
	out[ipv4(224, 0, 0, 251)] = struct{}{}
	for _, ip := range publicDsts {
		out[ip] = struct{}{}
	}
	return out
}

// IPString formats a uint32 IPv4 address.
func IPString(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

// FillRecord writes one verification flow record. Returns true when the flow is AV traffic.
func (lab *VerificationLab) FillRecord(rec []byte, avRatio float64, rng *rand.Rand, uptimeMS uint32) bool {
	if rng.Float64() < avRatio {
		lab.fillAV(rec, rng, uptimeMS)
		return true
	}
	lab.fillIT(rec, rng, uptimeMS)
	return false
}

func (lab *VerificationLab) pickRole(rng *rand.Rand, role DeviceRole) Endpoint {
	idxs := lab.byRole[role]
	if len(idxs) == 0 {
		return lab.Endpoints[0]
	}
	return lab.Endpoints[idxs[rng.IntN(len(idxs))]]
}

func (lab *VerificationLab) fillAV(rec []byte, rng *rand.Rand, uptimeMS uint32) {
	pattern := rng.IntN(7)
	var src, dst uint32
	var srcPort, dstPort uint16
	var proto uint8 = 17
	volume := volumeAV

	switch pattern {
	case 0: // Dante audio multicast or control unicast
		ep := lab.pickRole(rng, RoleDante)
		src = ep.IP
		deviceIdx := byte(parseHostOctet(ep.IP))
		if rng.Float64() < 0.3 {
			dst = lab.pickRole(rng, RoleDante).IP
			if dst == src && len(lab.byRole[RoleDante]) > 1 {
				dst = lab.Endpoints[lab.byRole[RoleDante][1]].IP
			}
			srcPort = uint16(8700 + rng.IntN(9))
			dstPort = uint16(8700 + rng.IntN(9))
			volume = volumeSmall
		} else {
			dst = ipv4(239, 255, 0, deviceIdx)
			srcPort = uint16(14336 + rng.IntN(512))
			dstPort = uint16(5004 + rng.IntN(996)) // 5004-5999 RTP-ish
		}
	case 1: // NDI discovery or high-port video
		srcEP := lab.pickRole(rng, RoleNDI)
		src = srcEP.IP
		if rng.Float64() < 0.4 {
			dst = lab.pickRole(rng, RoleNDI).IP
			srcPort = 5353
			dstPort = uint16(5960 + rng.IntN(10))
			volume = volumeSmall
		} else {
			dstEP := lab.pickRole(rng, RoleNDI)
			for dstEP.IP == src && len(lab.byRole[RoleNDI]) > 1 {
				dstEP = lab.pickRole(rng, RoleNDI)
			}
			dst = dstEP.IP
			srcPort = uint16(60000 + rng.IntN(8000))
			dstPort = uint16(60000 + rng.IntN(8000))
		}
	case 2: // ST2110 / RTP multicast
		ep := lab.pickRole(rng, RoleST2110)
		src = ep.IP
		host := parseHostOctet(ep.IP)
		if rng.Float64() < 0.5 {
			dst = ipv4(239, 69, 1, host)
		} else {
			dst = ipv4(239, 1, 2, host)
		}
		srcPort, dstPort = st2110Ports(rng)
	case 3: // Encoder → AV control
		src = lab.pickRole(rng, RoleEncoder).IP
		dst = lab.pickRole(rng, RoleAVControl).IP
		srcPort = uint16(50000 + rng.IntN(10000))
		if rng.Float64() < 0.5 {
			dstPort = 443
		} else {
			dstPort = 554
		}
		proto = 6
		volume = volumeSmall
	case 4: // mDNS discovery
		src = lab.pickRole(rng, RoleMDNS).IP
		dst = ipv4(224, 0, 0, 251)
		srcPort = 5353
		dstPort = 5353
		volume = volumeSmall
	case 5: // High-bandwidth ST2110-style multicast
		ep := lab.pickRole(rng, RoleHighBW)
		src = ep.IP
		host := parseHostOctet(ep.IP)
		if rng.Float64() < 0.5 {
			dst = ipv4(239, 1, 2, host)
		} else {
			dst = ipv4(239, 69, 1, host)
		}
		srcPort, dstPort = st2110Ports(rng)
		volume = volumeLarge
	default: // AV control / PTZ / matrix
		src = lab.pickRole(rng, RoleAVControl).IP
		dst = lab.pickRole(rng, RoleAVControl).IP
		if src == dst && len(lab.byRole[RoleAVControl]) > 1 {
			idxs := lab.byRole[RoleAVControl]
			dst = lab.Endpoints[idxs[1]].IP
		}
		srcPort = uint16(80 + rng.IntN(100))
		dstPort = []uint16{80, 443, 554, 9999}[rng.IntN(4)]
		proto = 6
		volume = volumeSmall
	}

	bytes, pkts, first, last := volume.sample(rng, uptimeMS)
	tos := uint8(0)
	tcpFlags := uint8(0)
	if proto == 6 {
		tcpFlags = 0x18
	} else if rng.Float64() < 0.25 {
		tos = 0xb8
	}

	netflowv9.WriteRecordFields(rec, bytes, pkts, proto, tos, tcpFlags, srcPort, dstPort, src, dst, first, last)
}

func (lab *VerificationLab) fillIT(rec []byte, rng *rand.Rand, uptimeMS uint32) {
	src := lab.pickRole(rng, RoleIT).IP
	dst := publicDsts[rng.IntN(len(publicDsts))]
	srcPort := uint16(50000 + rng.IntN(15000))
	dstPort := itPorts[rng.IntN(len(itPorts))]
	proto := uint8(17)
	if rng.Float64() < 0.35 {
		proto = 6
	}

	bytes, pkts, first, last := volumeIT.sample(rng, uptimeMS)
	tcpFlags := uint8(0)
	if proto == 6 {
		tcpFlags = 0x18
	}
	netflowv9.WriteRecordFields(rec, bytes, pkts, proto, 0, tcpFlags, srcPort, dstPort, src, dst, first, last)
}

func parseHostOctet(ip uint32) byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return b[3]
}

// st2110Ports returns src/dst ports in the dynamic ST2110 range 16384-32767 (even preferred).
func st2110Ports(rng *rand.Rand) (srcPort, dstPort uint16) {
	span := 32767 - 16384 + 1
	pick := func() uint16 {
		p := uint16(16384 + rng.IntN(span))
		if rng.Float64() < 0.7 {
			p &^= 1 // prefer even
		}
		return p
	}
	return pick(), pick()
}

type volumeProfile struct {
	minBytes, maxBytes int
	minPkts, maxPkts   int
	maxSpanMS          uint32
}

var (
	volumeSmall = volumeProfile{minBytes: 512, maxBytes: 64 << 10, minPkts: 1, maxPkts: 50, maxSpanMS: 2000}
	volumeAV    = volumeProfile{minBytes: 64 << 10, maxBytes: 8 << 20, minPkts: 50, maxPkts: 8000, maxSpanMS: 4000}
	volumeLarge = volumeProfile{minBytes: 4 << 20, maxBytes: 64 << 20, minPkts: 5000, maxPkts: 200000, maxSpanMS: 8000}
	volumeIT    = volumeProfile{minBytes: 64, maxBytes: 256 << 10, minPkts: 1, maxPkts: 400, maxSpanMS: 600000}
)

func (v volumeProfile) sample(rng *rand.Rand, uptimeMS uint32) (bytes, pkts, first, last uint32) {
	span := rng.IntN(int(v.maxSpanMS))
	if span < 1 {
		span = 1
	}
	last = uptimeMS
	if uptimeMS > uint32(span) {
		first = uptimeMS - uint32(span)
	}
	byteRange := v.maxBytes - v.minBytes
	if byteRange < 1 {
		byteRange = 1
	}
	pktsRange := v.maxPkts - v.minPkts
	if pktsRange < 1 {
		pktsRange = 1
	}
	bytes = uint32(v.minBytes + rng.IntN(byteRange))
	pkts = uint32(v.minPkts + rng.IntN(pktsRange))
	return bytes, pkts, first, last
}

// ReadRecordFields decodes a verification record for tests.
func ReadRecordFields(rec []byte) (srcIP, dstIP uint32, srcPort, dstPort uint16, proto uint8) {
	proto = rec[8]
	srcPort = binary.BigEndian.Uint16(rec[11:13])
	srcIP = binary.BigEndian.Uint32(rec[13:17])
	dstIP = binary.BigEndian.Uint32(rec[17:21])
	dstPort = binary.BigEndian.Uint16(rec[21:23])
	return srcIP, dstIP, srcPort, dstPort, proto
}
