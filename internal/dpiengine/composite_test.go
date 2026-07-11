package dpiengine

import "testing"

func TestParseHTTPHost(t *testing.T) {
	host := ParseHTTPHost([]byte("GET / HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	if host != "example.com" {
		t.Fatalf("expected example.com, got %q", host)
	}
}

func TestIsQUICInitial(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0xc0
	packet[4] = 0x01
	if !IsQUICInitial(packet) {
		t.Fatal("expected QUIC v1 initial")
	}
}
