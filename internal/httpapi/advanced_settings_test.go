package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
)

func TestRecommendedSettingsPreviewDoesNotChangeRuntimeOrExposeSecrets(t *testing.T) {
	cfg := config.Config{Mode: config.ModeEdge, ConfigurationMode: config.ConfigurationManual, MySQLDSN: "secret-dsn", CookieSecret: "secret-cookie", FRPTransportTLS: false}
	s := NewServer(cfg, nil)
	defer s.core.Close()
	response := httptest.NewRecorder()
	s.getRecommendedSystemSettings(response, httptest.NewRequest("GET", "/api/v1/admin/system-settings/recommended", nil))
	if s.getConfig().FRPTransportTLS || s.getConfig().ConfigurationMode != config.ConfigurationManual {
		t.Fatal("GET preview must not change runtime settings")
	}
	if strings.Contains(response.Body.String(), "secret-dsn") || strings.Contains(response.Body.String(), "secret-cookie") {
		t.Fatal("public settings must not expose credentials")
	}
}

func TestAdvancedManualSavePreservesNodeAndDurationOverrides(t *testing.T) {
	cfg := config.Config{Mode: config.ModeController, ConfigurationMode: config.ConfigurationManual, ConfigPath: t.TempDir() + "/server.json", FRPServerAddr: "frp.example", FRPServerPort: 7000, Node: config.NodeRuntimeConfig{Tag: "keep", FRPAdvertiseAddr: "frp.example", FRPBindPort: 7000}}
	s := NewServer(cfg, nil)
	defer s.core.Close()
	response := httptest.NewRecorder()
	s.updateSystemSettings(response, httptest.NewRequest("PUT", "/api/v1/admin/system-settings", strings.NewReader(`{"configuration_mode":"manual","frp_transport_tls":false,"runtime_token_ttl":"2h","embedded_frps_enabled":false}`)))
	if response.Code != 200 {
		t.Fatalf("save failed: %s", response.Body.String())
	}
	actual := s.getConfig()
	if actual.Node != cfg.Node || actual.FRPServerPort != 7000 || actual.RuntimeTokenTTL != 2*time.Hour || actual.FRPTransportTLS {
		t.Fatal("advanced-only save changed node settings or ignored manual overrides")
	}
}

func TestRestartNoticePersistsAcrossUnchangedSave(t *testing.T) {
	s := NewServer(config.Config{}, nil)
	defer s.core.Close()
	if !s.noteSettingsRestart(config.Config{}, true) || !s.noteSettingsRestart(config.Config{}, false) {
		t.Fatal("restart notice must persist until a new process starts")
	}
}

func TestTransportTuningSaveDoesNotChangeEdgePermissions(t *testing.T) {
	cfg := config.Config{Mode: config.ModeEdge, ConfigurationMode: config.ConfigurationAutomatic, ConfigPath: t.TempDir() + "/server.json", Node: config.NodeRuntimeConfig{Tag: "keep", Selectable: false}, Edge: config.EdgeConfig{ControllerAdministrationEnabled: true, Reporting: config.EdgeReportingConfig{ClientPresence: true}, RemoteCommands: config.EdgeRemoteCommandsConfig{BlockIP: true}}}
	s := NewServer(cfg, nil)
	defer s.core.Close()
	response := httptest.NewRecorder()
	s.updateSystemSettings(response, httptest.NewRequest("PUT", "/api/v1/admin/system-settings", strings.NewReader(`{"connection_tuning":{"tcp_keepalive_seconds":300,"enable_mtls_session_resumption":true}}`)))
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	actual := s.getConfig()
	if actual.Edge != cfg.Edge || actual.Node != cfg.Node || actual.ConnectionTuning.TCPKeepaliveSeconds != 300 || !actual.ConnectionTuning.EnableMTLSSessionResumption || actual.FRPTransportTLS {
		t.Fatal("advanced tuning changed ordinary settings or was not saved")
	}
	if !strings.Contains(response.Body.String(), `"restart_required":true`) {
		t.Fatal("tuning changes need a restart")
	}
}

func TestRenderedClientUsesConfiguredTCPMux(t *testing.T) {
	s := NewServer(config.Config{ConnectionTuning: config.ConnectionTuning{DisableTCPMux: true, TCPMuxKeepaliveSeconds: 45}}, nil)
	defer s.core.Close()
	text := s.renderFrpcConfig(&db.User{ID: 1}, "lease", "runtime", nil)
	if !strings.Contains(text, "transport.tcpMux = false") || !strings.Contains(text, "transport.tcpMuxKeepaliveInterval = 45") {
		t.Fatal("client and server TCP mux config must match")
	}
}
