package client

import (
	"context"
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func TestConnectorRejectsAlternativeTransportsAndPlaintext(t *testing.T) {
	for _, protocol := range []string{"quic", "kcp", "websocket", "wss", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			enabled, mux := true, false
			cfg := &v1.ClientCommonConfig{Transport: v1.ClientTransportConfig{Protocol: protocol, TCPMux: &mux, TLS: v1.TLSClientConfig{Enable: &enabled}}}
			connector := NewConnector(context.Background(), cfg)
			defer connector.Close()
			if err := connector.Open(); err == nil {
				t.Fatal("alternative transport was accepted")
			}
			if conn, err := connector.Connect(); err == nil {
				conn.Close()
				t.Fatal("direct Connect bypassed policy")
			}
		})
	}
	disabled, mux := false, false
	connector := NewConnector(context.Background(), &v1.ClientCommonConfig{Transport: v1.ClientTransportConfig{Protocol: "tcp", TCPMux: &mux, TLS: v1.TLSClientConfig{Enable: &disabled}}})
	defer connector.Close()
	if err := connector.Open(); err == nil {
		t.Fatal("plaintext Open was accepted")
	}
	if conn, err := connector.Connect(); err == nil {
		conn.Close()
		t.Fatal("plaintext Connect was accepted")
	}
}
