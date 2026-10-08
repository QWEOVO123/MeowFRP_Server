package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"frp-control-server/internal/config"
)

func TestEdgeSettingsCanEnableEmbeddedFRPWithoutResettingTLS(t *testing.T) {
	s := NewServer(config.Config{Mode: config.ModeEdge, ConfigPath: t.TempDir() + "/server.json", FRPTransportTLS: true}, nil)
	defer s.core.Close()
	req := httptest.NewRequest("PUT", "/api/v1/admin/system-settings", strings.NewReader(`{"embedded_frps_enabled":true}`))
	response := httptest.NewRecorder()
	s.updateSystemSettings(response, req)
	if response.Code != 200 {
		t.Fatalf("settings failed: %s", response.Body.String())
	}
	cfg := s.getConfig()
	if !cfg.EmbeddedFRPEnabled || !cfg.FRPTransportTLS {
		t.Fatal("enable request must preserve omitted TLS settings")
	}
	var result struct {
		RestartRequired bool `json:"restart_required"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || !result.RestartRequired {
		t.Fatal("enabling the FRP listener must require a restart")
	}
}

func TestUpdateSystemSettingsAcceptsReadOnlyPKIStatus(t *testing.T) {
	req := httptest.NewRequest("PUT", "/api/v1/admin/system-settings", strings.NewReader(`{
		"controller": {
			"edge_access_enabled": true,
			"listen_addr": "0.0.0.0:9443",
			"public_address": "controller.example.com:9443",
			"heartbeat_interval_seconds": 5,
			"pki_configured": true
		}
	}`))
	var payload updateSystemSettingsRequest
	if err := readJSON(req, &payload); err != nil {
		t.Fatalf("read settings request: %v", err)
	}
	if payload.Controller == nil || !payload.Controller.PKIConfigured {
		t.Fatalf("PKI status was not decoded: %#v", payload.Controller)
	}
}

func TestUpdateSystemSettingsStillRejectsUnknownControllerFields(t *testing.T) {
	req := httptest.NewRequest("PUT", "/api/v1/admin/system-settings", strings.NewReader(`{
		"controller": {"pki_configured_typo": true}
	}`))
	var payload updateSystemSettingsRequest
	if err := readJSON(req, &payload); err == nil {
		t.Fatal("expected an unknown controller field to be rejected")
	}
}

func TestReadJSONRejectsTrailingJSONValue(t *testing.T) {
	req := httptest.NewRequest("PUT", "/api/v1/admin/system-settings", strings.NewReader(`{"frp_server_addr":"example.test"} {"frp_server_port":7000}`))
	var payload updateSystemSettingsRequest
	if err := readJSON(req, &payload); err == nil {
		t.Fatal("expected trailing JSON value to be rejected")
	}
}
