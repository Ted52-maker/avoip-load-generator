package traffic

import (
	"encoding/binary"
	"math/rand/v2"
	"net"
	"testing"
)

func TestNewVerificationLabCountAndRoles(t *testing.T) {
	lab := NewVerificationLab(50)
	if len(lab.Endpoints) != 50 {
		t.Fatalf("expected 50 endpoints, got %d", len(lab.Endpoints))
	}

	wantRoles := map[DeviceRole]int{
		RoleDante:     8,
		RoleNDI:       8,
		RoleST2110:    6,
		RoleEncoder:   4,
		RoleMDNS:      2,
		RoleHighBW:    6,
		RoleAVControl: 4,
		RoleIT:        12,
	}
	for role, want := range wantRoles {
		if got := len(lab.byRole[role]); got != want {
			t.Errorf("role %s: want %d endpoints, got %d", role, want, got)
		}
	}

	if lab.Endpoints[0].IP != ipv4(192, 168, 10, 11) {
		t.Fatalf("first dante IP = %s", IPString(lab.Endpoints[0].IP))
	}
	if lab.Endpoints[len(lab.Endpoints)-1].IP != ipv4(192, 168, 128, 112) {
		t.Fatalf("last it IP = %s", IPString(lab.Endpoints[len(lab.Endpoints)-1].IP))
	}
}

func TestFillVerificationRecordUsesLabIPsOnly(t *testing.T) {
	lab := NewVerificationLab(50)
	allowed := lab.AllowedDestinations()
	rng := rand.New(rand.NewPCG(1, 2))
	rec := make([]byte, 31)

	for i := 0; i < 500; i++ {
		lab.FillRecord(rec, 0.78, rng, 10000)
		src, dst, _, _, _ := ReadRecordFields(rec)
		if _, ok := allowed[src]; !ok {
			t.Fatalf("flow %d: src %s not in lab allowlist", i, IPString(src))
		}
		if _, ok := allowed[dst]; !ok {
			t.Fatalf("flow %d: dst %s not in lab allowlist", i, IPString(dst))
		}
	}
}

func TestFillVerificationRecordDeterministicMulticast(t *testing.T) {
	lab := NewVerificationLab(50)
	rng := rand.New(rand.NewPCG(99, 1))
	rec := make([]byte, 31)

	var danteIP uint32
	for _, ep := range lab.Endpoints {
		if ep.Role == RoleDante {
			danteIP = ep.IP
			break
		}
	}
	if danteIP == 0 {
		t.Fatal("no dante endpoint")
	}

	wantDst := ipv4(239, 255, 0, parseHostOctet(danteIP))
	for try := 0; try < 2000; try++ {
		lab.fillAV(rec, rng, 5000)
		src, dst, _, _, proto := ReadRecordFields(rec)
		if src == danteIP && proto == 17 && dst == wantDst {
			return
		}
	}
	t.Fatalf("never saw deterministic dante multicast for %s -> %s", IPString(danteIP), IPString(wantDst))
}

func TestFillRecordDstFieldsNonZero(t *testing.T) {
	lab := NewVerificationLab(50)
	rng := rand.New(rand.NewPCG(3, 4))
	rec := make([]byte, 31)

	for i := 0; i < 200; i++ {
		lab.FillRecord(rec, 0.78, rng, 5000)
		src, dst, srcPort, dstPort, _ := ReadRecordFields(rec)
		if src == 0 {
			t.Fatalf("flow %d: src IP zero", i)
		}
		if dst == 0 {
			t.Fatalf("flow %d: dst IP zero", i)
		}
		if srcPort == 0 {
			t.Fatalf("flow %d: src port zero", i)
		}
		if dstPort == 0 {
			t.Fatalf("flow %d: dst port zero", i)
		}
	}
}

func TestST2110PortsInRange(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	for i := 0; i < 100; i++ {
		src, dst := st2110Ports(rng)
		for _, p := range []uint16{src, dst} {
			if p < 16384 || p > 32767 {
				t.Fatalf("port %d outside ST2110 range 16384-32767", p)
			}
		}
	}
}

func TestFillRecordST2110MulticastDst(t *testing.T) {
	lab := NewVerificationLab(50)
	rng := rand.New(rand.NewPCG(77, 2))
	rec := make([]byte, 31)

	for try := 0; try < 3000; try++ {
		lab.fillAV(rec, rng, 5000)
		src, dst, _, dstPort, proto := ReadRecordFields(rec)
		if proto != 17 {
			continue
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, dst)
		ip := net.IP(b)
		if !ip.IsMulticast() {
			continue
		}
		isST2110MC := b[0] == 239 && ((b[1] == 69 && b[2] == 1) || (b[1] == 1 && b[2] == 2))
		if isST2110MC && dstPort >= 16384 && dstPort <= 32767 {
			_ = src
			return
		}
	}
	t.Fatal("never saw ST2110-style multicast with port 16384-32767")
}

func TestFillRecordAVRatio(t *testing.T) {
	lab := NewVerificationLab(50)
	rng := rand.New(rand.NewPCG(42, 7))
	rec := make([]byte, 31)

	var av int
	const n = 1000
	for i := 0; i < n; i++ {
		if lab.FillRecord(rec, 0.78, rng, 1000) {
			av++
		}
	}
	ratio := float64(av) / n
	if ratio < 0.65 || ratio > 0.90 {
		t.Fatalf("av ratio %f outside expected band around 0.78", ratio)
	}
}
