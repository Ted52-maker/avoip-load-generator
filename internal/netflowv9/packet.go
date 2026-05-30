// Package netflowv9 builds binary NetFlow v9 export datagrams compatible with
// goflow2's decoder (netsampler/goflow2/v3/decoders/netflow). Templates are
// registered per (exporter address, version, observation domain, template id);
// we give each tenant a distinct SourceId (observation domain) in the header.
package netflowv9

import (
	"encoding/binary"
)

// Template and field layout — fixed sizes so data records are dense and fast.
const (
	TemplateID   = 256
	RecordSize   = 31 // sum of all field lengths below
	MaxUDPBytes  = 1200 // stay under typical path MTU for UDP
	HeaderSize   = 20
	FlowSetHdr   = 4
	TemplateFSLen = 52 // 4 (hdr) + 48 (one template record with 11 fields)
)

// fieldSpec describes our IPv4 flow template (common enterprise exporter shape).
var fieldSpecs = [][2]uint16{
	{1, 4},   // IN_BYTES
	{2, 4},   // IN_PKTS
	{4, 1},   // PROTOCOL
	{5, 1},   // SRC_TOS
	{6, 1},   // TCP_FLAGS
	{7, 2},   // L4_SRC_PORT
	{8, 4},   // IPV4_SRC_ADDR
	{9, 4},   // IPV4_DST_ADDR
	{12, 2},  // L4_DST_PORT
	{21, 4},  // LAST_SWITCHED (sys uptime ms at end of flow)
	{22, 4},  // FIRST_SWITCHED
}

// DataFlowSetMaxRecords returns how many complete records fit in one UDP
// datagram given the fixed template+header overhead.
func DataFlowSetMaxRecords() int {
	avail := MaxUDPBytes - HeaderSize - TemplateFSLen - FlowSetHdr
	if avail < RecordSize {
		return 1
	}
	n := avail / RecordSize
	// FlowSet length must be multiple of 4; trim if padding would overflow max
	for n > 0 {
		dataLen := n * RecordSize
		pad := (4 - (dataLen % 4)) % 4
		total := HeaderSize + TemplateFSLen + FlowSetHdr + dataLen + pad
		if total <= MaxUDPBytes {
			return n
		}
		n--
	}
	return 1
}

// appendTemplateFlowSet writes the template flow set (id 0) at off in buf.
func appendTemplateFlowSet(buf []byte, off int) int {
	binary.BigEndian.PutUint16(buf[off+0:off+2], 0) // template flow set id
	binary.BigEndian.PutUint16(buf[off+2:off+4], TemplateFSLen)
	tOff := off + 4
	binary.BigEndian.PutUint16(buf[tOff+0:tOff+2], TemplateID)
	binary.BigEndian.PutUint16(buf[tOff+2:tOff+4], uint16(len(fieldSpecs)))
	fOff := tOff + 4
	for _, spec := range fieldSpecs {
		binary.BigEndian.PutUint16(buf[fOff+0:fOff+2], spec[0])
		binary.BigEndian.PutUint16(buf[fOff+2:fOff+4], spec[1])
		fOff += 4
	}
	return off + TemplateFSLen
}

// BuildExportPacket writes a complete NetFlow v9 UDP payload: header, template
// flow set (so collectors without persistent template cache stay happy), and a
// data flow set with n contiguous records starting at recordWriter offset.
// Returns the total bytes written.
func BuildExportPacket(
	buf []byte,
	countFlowSets uint16,
	sysUptimeMS, unixSecs, seq, sourceID uint32,
	n int,
	writeRecord func(i int, rec []byte),
) int {
	if n <= 0 {
		n = 1
	}
	maxN := DataFlowSetMaxRecords()
	if n > maxN {
		n = maxN
	}

	off := 0
	binary.BigEndian.PutUint16(buf[off+0:off+2], 9)
	off += 2
	binary.BigEndian.PutUint16(buf[off+0:off+2], countFlowSets)
	off += 2
	binary.BigEndian.PutUint32(buf[off+0:off+4], sysUptimeMS)
	off += 4
	binary.BigEndian.PutUint32(buf[off+0:off+4], unixSecs)
	off += 4
	binary.BigEndian.PutUint32(buf[off+0:off+4], seq)
	off += 4
	binary.BigEndian.PutUint32(buf[off+0:off+4], sourceID)
	off += 4

	off = appendTemplateFlowSet(buf, off)

	dataBodyLen := n * RecordSize
	pad := (4 - (dataBodyLen % 4)) % 4
	dataFSLen := FlowSetHdr + dataBodyLen + pad

	binary.BigEndian.PutUint16(buf[off+0:off+2], TemplateID)
	binary.BigEndian.PutUint16(buf[off+2:off+4], uint16(dataFSLen))
	off += 4

	recOff := off
	for i := 0; i < n; i++ {
		rec := buf[recOff+i*RecordSize : recOff+(i+1)*RecordSize]
		writeRecord(i, rec)
	}
	off += dataBodyLen
	for p := 0; p < pad; p++ {
		buf[off+p] = 0
	}
	off += pad
	return off
}

// WriteRecordFields writes one data record in big-endian form (field order
// matches fieldSpecs).
func WriteRecordFields(
	rec []byte,
	inBytes, inPkts uint32,
	proto, tos, tcpFlags uint8,
	srcPort, dstPort uint16,
	srcIP, dstIP uint32,
	firstSwitchedMS, lastSwitchedMS uint32,
) {
	_ = rec[RecordSize-1]
	binary.BigEndian.PutUint32(rec[0:4], inBytes)
	binary.BigEndian.PutUint32(rec[4:8], inPkts)
	rec[8] = proto
	rec[9] = tos
	rec[10] = tcpFlags
	binary.BigEndian.PutUint16(rec[11:13], srcPort)
	binary.BigEndian.PutUint32(rec[13:17], srcIP)
	binary.BigEndian.PutUint32(rec[17:21], dstIP)
	binary.BigEndian.PutUint16(rec[21:23], dstPort)
	binary.BigEndian.PutUint32(rec[23:27], lastSwitchedMS)
	binary.BigEndian.PutUint32(rec[27:31], firstSwitchedMS)
}
