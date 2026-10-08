package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecommendedOnlyEnablesFRPAndDisablesFRPTLS(t *testing.T) {
	cfg := Config{
		Mode:               ModeController,
		EmbeddedFRPEnabled: false, FRPTransportTLS: true,
		FRPBindAddr: "127.0.0.1", FRPProxyBindAddr: "127.0.0.2",
		SessionTTL: 2 * time.Hour, RuntimeTokenTTL: 2 * time.Hour, UDPConnectionTTL: 20 * time.Second,
		ClientConfigComment: "keep-comment",
		ConnectionTuning:    ConnectionTuning{TCPKeepaliveSeconds: 300, EnableMTLSSessionResumption: true},
		Node:                NodeRuntimeConfig{PublicAPIURL: "https://center.example/api", FRPBindPort: 7443, PortRangeStart: 21000, PortRangeEnd: 22000},
		Controller:          ControllerConfig{ListenAddr: "127.0.0.1:7443", PublicAddress: "custom.example:7443", HeartbeatIntervalSeconds: 17, TLS: TLSFiles{CACertificateBase64: "keep-ca"}},
		Edge:                EdgeConfig{NodeID: "keep-identity", Reporting: EdgeReportingConfig{RuntimeLogs: true}},
	}
	expected := cfg
	expected.EmbeddedFRPEnabled = true
	expected.FRPTransportTLS = false
	ApplyRecommended(&cfg)
	if cfg != expected {
		t.Fatal("automatic mode must change only embedded FRP and client FRP TLS")
	}
}

func TestLegacyFileUsesManualModeWithoutChangingSwitches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.json")
	t.Setenv("FRP_CONTROL_CONFIG", path)
	t.Setenv("FRP_CONTROL_EMBEDDED_FRPS_ENABLED", "")
	t.Setenv("FRP_CONTROL_FRP_TRANSPORT_TLS", "")
	cfg := defaults()
	cfg.ConfigurationMode = ""
	cfg.Mode = ModeController
	cfg.Initialized = true
	cfg.MySQLDSN = "dsn"
	cfg.InitialAdmin = InitialAdminConfig{Username: "admin", PasswordHash: "hash"}
	cfg.EmbeddedFRPEnabled = false
	cfg.FRPTransportTLS = false
	if err := WriteFileConfig(path, cfg.FileConfig()); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ConfigurationMode != ConfigurationManual || loaded.EmbeddedFRPEnabled || loaded.FRPTransportTLS {
		t.Fatal("legacy overrides must be preserved")
	}
}
