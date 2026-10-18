package httpapi

import (
	"context"
	"encoding/json"
	"frp-control-server/internal/cluster"
	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/edgestate"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFRPTrustPublicAndDatabaseIndependent(t *testing.T) {
	cfg := config.Config{Mode: config.ModeController, Initialized: true, FRPTransportTLS: true, ConfigPath: filepath.Join(t.TempDir(), "node.json")}
	s := NewServer(cfg, nil)
	defer s.core.Close()
	if err := s.prepareFRPIdentity(cfg); err != nil {
		t.Fatal(err)
	}
	s.fault.mu.Lock()
	s.fault.closed, s.fault.databaseFailed = true, true
	s.fault.mu.Unlock()
	for _, path := range []string{"/api/v1/client/frp-transport", "/api/v1/client/frp-trust"} {
		response := httptest.NewRecorder()
		s.Routes().ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != 200 || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("public trust unavailable during database fault", response.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["enabled"] != true || body["node_id"] != "controller" {
			t.Fatal("incorrect runtime state")
		}
		if (path == "/api/v1/client/frp-trust") != (body["ca_pem"] != "") {
			t.Fatal("trust payload on wrong endpoint")
		}
		if strings.Contains(response.Body.String(), "PRIVATE KEY") {
			t.Fatal("private key exposed")
		}
	}
	cfg.FRPTransportTLS = false
	s.setRuntime(cfg, nil)
	response := httptest.NewRecorder()
	s.Routes().ServeHTTP(response, httptest.NewRequest("GET", "/api/v1/client/frp-transport", nil))
	if !strings.Contains(response.Body.String(), `"enabled":true`) {
		t.Fatal("mandatory TLS state must ignore legacy disable")
	}
	generated := s.renderFrpcConfig(&db.User{ID: 1}, "lease_test", "test_secret", nil)
	if !strings.Contains(generated, "transport.tls.trustFromAPI = true") || !strings.Contains(generated, "transport.tls.enable = true") || !strings.Contains(generated, `transport.protocol = "tcp"`) || strings.Contains(generated, "BEGIN CERTIFICATE") || strings.Contains(generated, "PRIVATE KEY") {
		t.Fatal("runtime TOML must adapt without persisting trust")
	}
	response = httptest.NewRecorder()
	s.Routes().ServeHTTP(response, httptest.NewRequest("POST", "/api/v1/admin/frp-tls/reset", strings.NewReader(`{}`)))
	if response.Code == 200 {
		t.Fatal("unauthorized reset accepted")
	}
}

func TestRemoteFRPResetPermissionAndCrashReplay(t *testing.T) {
	cfg := config.Config{Mode: config.ModeEdge, Initialized: true, ConfigPath: filepath.Join(t.TempDir(), "node.json"), Edge: config.EdgeConfig{NodeID: "edge-1", ControllerAdministrationEnabled: true, RemoteCommands: config.EdgeRemoteCommandsConfig{ChangeRuntimeSettings: true}}}
	state, err := edgestate.Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	s := NewServer(cfg, nil, WithEdgeRuntime(state, nil))
	defer s.core.Close()
	if err := s.prepareFRPIdentity(cfg); err != nil {
		t.Fatal(err)
	}
	command := cluster.NodeCommand{CommandID: "reset-1", Command: "reset_frp_tls", Payload: json.RawMessage(`{}`), ExpiresAt: time.Now().Add(time.Minute)}
	// Emulate a crash after resetting the key, but before recording the command result.
	if _, _, err := state.BeginCommand(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if err := s.core.ResetTLSIdentity(cfg, command.CommandID); err != nil {
		t.Fatal(err)
	}
	before, _ := s.core.TLSPublic(false)
	result := s.HandleEdgeCommand(context.Background(), command)
	if result.Status != "succeeded" {
		t.Fatal(result.Error)
	}
	after, _ := s.core.TLSPublic(false)
	if before.Generation != after.Generation {
		t.Fatal("crash replay rotated twice")
	}
	cfg.Edge.RemoteCommands.ChangeRuntimeSettings = false
	s.setRuntime(cfg, nil)
	command.CommandID = "reset-2"
	if result := s.HandleEdgeCommand(context.Background(), command); result.Status != "failed" {
		t.Fatal("remote reset bypassed local permission")
	}
}
