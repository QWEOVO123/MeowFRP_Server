package frpcore

import (
	"testing"

	"frp-control-server/internal/config"
)

func TestBuildEmbeddedFRPSConfig(t *testing.T) {
	cfg, err := BuildEmbeddedFRPSConfig(config.Config{
		HTTPAddr:           ":18080",
		EmbeddedFRPEnabled: true,
		FRPBindAddr:        "127.0.0.1",
		FRPProxyBindAddr:   "127.0.0.1",
		FRPServerPort:      17000,
		FRPTransportTLS:    true,
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if cfg.BindAddr != "127.0.0.1" {
		t.Fatalf("unexpected bind addr %q", cfg.BindAddr)
	}
	if cfg.BindPort != 17000 {
		t.Fatalf("unexpected bind port %d", cfg.BindPort)
	}
	if !cfg.Transport.TLS.Force {
		t.Fatal("expected tls force to follow app config")
	}
	if len(cfg.HTTPPlugins) != 1 {
		t.Fatalf("expected one http plugin, got %d", len(cfg.HTTPPlugins))
	}
	plugin := cfg.HTTPPlugins[0]
	if plugin.Addr != "http://127.0.0.1:18080" {
		t.Fatalf("unexpected plugin addr %q", plugin.Addr)
	}
	if plugin.Path != "/api/v1/frp/plugin" {
		t.Fatalf("unexpected plugin path %q", plugin.Path)
	}
}

func TestControlPluginAddrNormalizesWildcardBind(t *testing.T) {
	got := controlPluginAddr("0.0.0.0:8080")
	if got != "http://127.0.0.1:8080" {
		t.Fatalf("unexpected plugin addr %q", got)
	}
}
