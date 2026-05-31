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

func TestFieldSpecsRFC3954DestinationIDs(t *testing.T) {
	var hasDstIP, hasDstPort bool
	for _, spec := range fieldSpecs {
		switch spec[0] {
		case 12:
			if spec[1] != 4 {
				t.Fatalf("IPV4_DST_ADDR (12) want len 4, got %d", spec[1])
			}
			hasDstIP = true
		case 11:
			if spec[1] != 2 {
				t.Fatalf("L4_DST_PORT (11) want len 2, got %d", spec[1])
			}
			hasDstPort = true
		case 9:
			t.Fatalf("field 9 is SRC_MASK per RFC 3954, must not appear in template")
		}
	}
	if !hasDstIP || !hasDstPort {
		t.Fatalf("template missing destination fields: ip=%v port=%v", hasDstIP, hasDstPort)
	}
}

func TestWriteRecordFieldsDestinationAtExpectedOffsets(t *testing.T) {
	rec := make([]byte, RecordSize)
	dstIP := uint32(0xef010203) // 239.1.2.3
	dstPort := uint16(20000)
	WriteRecordFields(rec, 1000, 10, 17, 0, 0, 5000, dstPort, 0x0a000001, dstIP, 100, 200)

	gotIP := binary.BigEndian.Uint32(rec[17:21])
	gotPort := binary.BigEndian.Uint16(rec[21:23])
	if gotIP != dstIP {
		t.Fatalf("dst IP at offset 17: got %08x want %08x", gotIP, dstIP)
	}
	if gotPort != dstPort {
		t.Fatalf("dst port at offset 21: got %d want %d", gotPort, dstPort)
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
