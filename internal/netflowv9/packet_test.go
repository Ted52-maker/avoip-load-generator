package netflowv9

import (
	"encoding/binary"
	"testing"
)

func TestBuildExportPacketLengthAndPadding(t *testing.T) {
	buf := make([]byte, MaxUDPBytes)
	n := DataFlowSetMaxRecords()
	if n < 1 {
		t.Fatalf("max records %d", n)
	}
	pkt := BuildExportPacket(buf, 2, 1000, 1_700_000_000, 1, 0xdeadbeef, n, func(i int, rec []byte) {
		for j := range rec {
			rec[j] = byte(i + j)
		}
	})
	if pkt%4 != 0 {
		t.Fatalf("packet length %d not multiple of 4", pkt)
	}
	if pkt > MaxUDPBytes {
		t.Fatalf("packet %d > max %d", pkt, MaxUDPBytes)
	}
	ver := binary.BigEndian.Uint16(buf[0:2])
	if ver != 9 {
		t.Fatalf("version %d", ver)
	}
}

func TestRecordSizeMatchesTemplate(t *testing.T) {
	var sum int
	for _, f := range fieldSpecs {
		sum += int(f[1])
	}
	if sum != RecordSize {
		t.Fatalf("RecordSize %d != sum of template %d", RecordSize, sum)
	}
}
