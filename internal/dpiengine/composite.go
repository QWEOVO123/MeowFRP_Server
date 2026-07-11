package dpiengine

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

const (
	maxInspectBytes = 8192
	maxFlowStates   = 8192
	flowStateTTL    = 3 * time.Minute
)

type CompositeEngine struct {
	mu     sync.Mutex
	states map[string]*flowState
}

type flowState struct {
	tlsBuffer      []byte
	inspectedBytes int
	ssPackets      int
	ssDetected     bool
	lastSeen       time.Time
}

func NewCompositeEngine() *CompositeEngine {
	return &CompositeEngine{states: map[string]*flowState{}}
}

func (e *CompositeEngine) Inspect(_ context.Context, sample TrafficSample) (Result, error) {
	if e == nil {
		return Result{}, nil
	}
	if len(sample.Payload) == 0 {
		return Result{}, nil
	}
	now := sample.ObservedAt
	if now.IsZero() {
		now = time.Now()
	}
	key := flowKey(sample.Flow, sample.Direction)
	e.mu.Lock()
	state := e.states[key]
	if state == nil {
		if len(e.states) >= maxFlowStates {
			e.cleanupLocked(now)
		}
		state = &flowState{}
		e.states[key] = state
	}
	state.lastSeen = now
	if state.inspectedBytes >= maxInspectBytes {
		e.mu.Unlock()
		return Result{}, nil
	}
	state.inspectedBytes += len(sample.Payload)
	findings := e.inspectLocked(sample, state)
	e.mu.Unlock()
	return Result{Findings: findings}, nil
}

func (e *CompositeEngine) inspectLocked(sample TrafficSample, state *flowState) []Finding {
	payload := sample.Payload
	var findings []Finding

	if host := ParseHTTPHost(payload); host != "" {
		findings = append(findings, Finding{
			Detector: "http",
			Protocol: "HTTP",
			Host:     host,
			Summary:  "http host detected",
		})
	}

	if sni := feedTLSClientHello(state, payload); sni != "" {
		findings = append(findings, Finding{
			Detector: "tls",
			Protocol: "TLS",
			SNI:      sni,
			Summary:  "tls sni detected",
		})
	}

	if IsQUICInitial(payload) {
		findings = append(findings, Finding{
			Detector: "quic",
			Protocol: "QUIC",
			Summary:  "quic initial detected",
		})
	}

	if detectEncryptedTunnel(state, payload) {
		findings = append(findings, Finding{
			Detector:   "encrypted_tunnel",
			Protocol:   "SS",
			Confidence: 0.72,
			Summary:    "encrypted tunnel heuristic matched",
		})
	}

	return findings
}

func (e *CompositeEngine) cleanupLocked(now time.Time) {
	for key, state := range e.states {
		if now.Sub(state.lastSeen) > flowStateTTL {
			delete(e.states, key)
		}
	}
}

func flowKey(flow FlowContext, direction Direction) string {
	return strings.Join([]string{
		flow.LeaseID,
		flow.ProxyName,
		flow.ProxyType,
		flow.RemoteAddr,
		string(direction),
	}, "|")
}

func ParseHTTPHost(data []byte) string {
	if len(data) < 16 || !looksLikeHTTP(data) {
		return ""
	}
	limit := len(data)
	if limit > 4096 {
		limit = 4096
	}
	if end := bytes.Index(data[:limit], []byte("\r\n\r\n")); end >= 0 {
		limit = end
	}
	lineStart := 0
	for lineStart < limit {
		lineEnd := lineStart
		for lineEnd < limit && data[lineEnd] != '\r' && data[lineEnd] != '\n' {
			lineEnd++
		}
		if valueStart := hostValueStart(data, lineStart, lineEnd); valueStart >= 0 {
			valueEnd := valueStart
			for valueEnd < lineEnd {
				b := data[valueEnd]
				if b == ' ' || b == '\t' || b == ':' {
					break
				}
				valueEnd++
			}
			if valueEnd > valueStart {
				return string(data[valueStart:valueEnd])
			}
			return ""
		}
		lineStart = lineEnd + 1
		if lineStart < limit && data[lineStart-1] == '\r' && data[lineStart] == '\n' {
			lineStart++
		}
	}
	return ""
}

func hostValueStart(data []byte, lineStart, lineEnd int) int {
	if lineEnd-lineStart < 5 {
		return -1
	}
	if !equalFoldByte(data[lineStart], 'h') ||
		!equalFoldByte(data[lineStart+1], 'o') ||
		!equalFoldByte(data[lineStart+2], 's') ||
		!equalFoldByte(data[lineStart+3], 't') ||
		data[lineStart+4] != ':' {
		return -1
	}
	start := lineStart + 5
	for start < lineEnd && (data[start] == ' ' || data[start] == '\t') {
		start++
	}
	return start
}

func equalFoldByte(actual byte, expectedLower byte) bool {
	if actual >= 'A' && actual <= 'Z' {
		actual += 'a' - 'A'
	}
	return actual == expectedLower
}

func looksLikeHTTP(data []byte) bool {
	prefixes := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "),
		[]byte("DELETE "), []byte("PATCH "), []byte("OPTIONS "),
		[]byte("CONNECT "),
	}
	for _, prefix := range prefixes {
		if bytes.HasPrefix(data, prefix) {
			return true
		}
	}
	return false
}

func feedTLSClientHello(state *flowState, data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if len(state.tlsBuffer) == 0 && data[0] != 0x16 {
		return ""
	}
	if len(state.tlsBuffer)+len(data) > maxInspectBytes {
		state.tlsBuffer = nil
		return ""
	}
	state.tlsBuffer = append(state.tlsBuffer, data...)
	if sni := parseTLSClientHelloSNI(state.tlsBuffer); sni != "" {
		state.tlsBuffer = nil
		return sni
	}
	return ""
}

func parseTLSClientHelloSNI(buffer []byte) string {
	offset := 0
	for offset+5 <= len(buffer) {
		if buffer[offset] != 0x16 {
			offset++
			continue
		}
		version := binary.BigEndian.Uint16(buffer[offset+1 : offset+3])
		if version < 0x0301 {
			offset++
			continue
		}
		recordLen := int(binary.BigEndian.Uint16(buffer[offset+3 : offset+5]))
		if recordLen <= 0 || recordLen > 16384 {
			offset++
			continue
		}
		if offset+5+recordLen > len(buffer) {
			return ""
		}
		if sni := parseClientHelloRecord(buffer[offset+5 : offset+5+recordLen]); sni != "" {
			return sni
		}
		offset += 5 + recordLen
	}
	return ""
}

func parseClientHelloRecord(record []byte) string {
	if len(record) < 4 || record[0] != 0x01 {
		return ""
	}
	hsLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if len(record)-4 < hsLen {
		return ""
	}
	pos := 4
	if pos+34 > 4+hsLen {
		return ""
	}
	pos += 34
	if pos >= len(record) {
		return ""
	}
	sidLen := int(record[pos])
	pos += 1 + sidLen
	if pos+2 > len(record) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(record[pos : pos+2]))
	pos += 2 + csLen
	if pos >= len(record) {
		return ""
	}
	compLen := int(record[pos])
	pos += 1 + compLen
	if pos+2 > len(record) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(record[pos : pos+2]))
	pos += 2
	end := pos + extLen
	if end > len(record) {
		end = len(record)
	}
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(record[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(record[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > end {
			return ""
		}
		if extType == 0x0000 {
			return parseSNIExtension(record[pos : pos+extDataLen])
		}
		pos += extDataLen
	}
	return ""
}

func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	pos := 2
	end := pos + listLen
	if end > len(data) {
		end = len(data)
	}
	if pos+3 > end {
		return ""
	}
	nameType := data[pos]
	nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
	pos += 3
	if nameType == 0x00 && nameLen > 0 && pos+nameLen <= end {
		return string(data[pos : pos+nameLen])
	}
	return ""
}

func IsQUICInitial(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	first := data[0]
	if first&0x80 == 0 || first&0x40 == 0 {
		return false
	}
	packetType := (first & 0x30) >> 4
	if packetType != 0 {
		return false
	}
	version := binary.BigEndian.Uint32(data[1:5])
	return version == 0x00000001
}

func detectEncryptedTunnel(state *flowState, data []byte) bool {
	if state.ssDetected || len(data) < 20 {
		return false
	}
	state.ssPackets++
	if state.ssPackets > 3 {
		return false
	}
	if looksLikeTLS(data) || looksLikeHTTP(data) || IsQUICInitial(data) || isKnownProtocol(data) {
		return false
	}
	if isLikelyEncryptedTunnel(data) {
		state.ssDetected = true
		return true
	}
	return false
}

func isLikelyEncryptedTunnel(data []byte) bool {
	avgPop := calcAvgPopcount(data)
	printableRatio := calcPrintableRatio(data)
	return avgPop >= 3.4 &&
		avgPop <= 4.6 &&
		printableRatio <= 35.0 &&
		isUniformDistribution(data) &&
		data[0] != 0x00 &&
		!hasProtocolStructure(data) &&
		!isKnownProtocol(data)
}

func calcAvgPopcount(data []byte) float64 {
	total := 0
	for _, b := range data {
		total += bitsInByte(b)
	}
	return float64(total) / float64(len(data))
}

func bitsInByte(b byte) int {
	count := 0
	for value := b; value != 0; value >>= 1 {
		count += int(value & 1)
	}
	return count
}

func calcPrintableRatio(data []byte) float64 {
	count := 0
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			count++
		}
	}
	return float64(count) / float64(len(data)) * 100
}

func isUniformDistribution(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	var counter [256]int
	for _, b := range data {
		counter[b]++
	}
	unique := 0
	for _, count := range counter {
		if count > 0 {
			unique++
		}
	}
	return unique >= 15 && float64(unique)/float64(len(data)) > 0.3
}

func hasProtocolStructure(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	same := 0
	for i := 1; i < 4; i++ {
		if data[i] == data[0] {
			same++
		}
	}
	if same >= 2 {
		return true
	}
	return data[1] == data[0]+1 && data[2] == data[1]+1
}

func isKnownProtocol(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	if bytes.HasPrefix(data, []byte("SSH-")) {
		return true
	}
	if len(data) >= 3 && data[0] == 0x03 && data[1] == 0x00 {
		return true
	}
	if bytes.HasPrefix(data, []byte{0x4a, 0x00, 0x00, 0x00, 0x0a}) {
		return true
	}
	if len(data) >= 8 && data[0] == 0x12 && data[1] == 0x01 {
		return true
	}
	return len(data) >= 8 && data[0] == 0x00 && data[4] == 0x00
}

func looksLikeTLS(data []byte) bool {
	return len(data) >= 3 && data[0] >= 0x14 && data[0] <= 0x17 && data[1] == 0x03 && data[2] <= 0x04
}
