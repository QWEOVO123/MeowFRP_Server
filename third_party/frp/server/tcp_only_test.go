package server

import (
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func TestTCPOnlyRejectsAdditionalTransportListeners(t *testing.T) {
	for _, protocol := range []string{"kcp", "quic", "ssh"} {
		t.Run(protocol, func(t *testing.T) {
			cfg := &v1.ServerConfig{TCPOnly: true}
			switch protocol {
			case "kcp":
				cfg.KCPBindPort = 1
			case "quic":
				cfg.QUICBindPort = 1
			case "ssh":
				cfg.SSHTunnelGateway.BindPort = 1
			}
			if service, err := NewServiceWithTLS(cfg, nil); err == nil {
				service.Close()
				t.Fatal("non-TCP listener accepted")
			}
		})
	}
}
