package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/edgestate"
)

func TestInitializeNodeRuntimeUsesPublicRequestHost(t *testing.T) {
	req := httptest.NewRequest("POST", "http://edge.example.com/api/v1/setup/edge", nil)
	req.RemoteAddr = "203.0.113.8:50000"
	cfg := config.Config{FRPServerPort: 7000, Node: config.NodeRuntimeConfig{FRPBindPort: 7000, PortRangeStart: 1024, PortRangeEnd: 65535}}
	initializeNodeRuntimeFromRequest(&cfg, req, "Edge A")
	if cfg.Node.FRPAdvertiseAddr != "edge.example.com" || cfg.Node.PublicAPIURL != "http://edge.example.com/api" {
		t.Fatalf("unexpected node defaults: %#v", cfg.Node)
	}
}

func TestNodeRangeIntersectsUserPolicyAndReservesServicePorts(t *testing.T) {
	cfg := config.Config{Mode: config.ModeController, HTTPAddr: ":8080", Controller: config.ControllerConfig{ListenAddr: ":9443"}, Node: config.NodeRuntimeConfig{FRPBindPort: 7000, PortRangeStart: 20000, PortRangeEnd: 30000}}
	policy, ok := intersectNodePortRange(&db.UserResourcePolicy{PortStart: 10000, PortEnd: 25000}, cfg)
	if !ok || policy.PortStart != 20000 || policy.PortEnd != 25000 {
		t.Fatalf("unexpected intersection: %#v, %v", policy, ok)
	}
	for _, port := range []int{7000, 8080, 9443} {
		cfg.Node.PortRangeStart = 1
		if err := validateNodeRemotePort(cfg, port); err == nil {
			t.Fatalf("reserved port %d was accepted", port)
		}
	}
}

func TestControllerDirectoryAlwaysIdentifiesSelf(t *testing.T) {
	req := httptest.NewRequest("GET", "https://controller.example.com/api/v1/public/nodes", nil)
	cfg := config.Config{Node: config.NodeRuntimeConfig{Tag: "Main", Selectable: true}}
	item := controllerDirectoryItem(cfg, req)
	if item == nil || item["node_id"] != "controller" || item["api_url"] != "https://controller.example.com/api" || item["online"] != true {
		t.Fatalf("unexpected controller directory item: %#v", item)
	}
}

func TestEdgeRuntimeSettingsCommandPersistsUnifiedNodeConfig(t *testing.T) {
	dir := t.TempDir()
	state, err := edgestate.Open(filepath.Join(dir, "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	cfg := config.Config{
		ConfigPath: filepath.Join(dir, "server.json"), Mode: config.ModeEdge, ConfigVersion: 2,
		Node: config.NodeRuntimeConfig{Tag: "Old", PublicAPIURL: "https://old.example/api", FRPAdvertiseAddr: "old.example", FRPBindPort: 7000, PortRangeStart: 10000, PortRangeEnd: 20000, Selectable: true},
		Edge: config.EdgeConfig{ControllerAdministrationEnabled: true, RemoteCommands: config.EdgeRemoteCommandsConfig{ChangeRuntimeSettings: true}},
	}
	target := config.NodeRuntimeConfig{Tag: "New", PublicAPIURL: "https://new.example/api", FRPAdvertiseAddr: "new.example", FRPBindPort: 7443, PortRangeStart: 22000, PortRangeEnd: 23000, Selectable: true}
	payload, _ := json.Marshal(target)
	server := &Server{cfg: cfg, edgeState: state}
	result := server.HandleEdgeCommand(context.Background(), cluster.NodeCommand{CommandID: "cmd-runtime", Command: "update_edge_runtime_settings", Payload: payload, ExpiresAt: time.Now().Add(time.Minute)})
	if result.Status != "succeeded" {
		t.Fatalf("command failed: %#v", result)
	}
	written, err := config.ReadFileConfig(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if written.Node != target || written.FRPServerAddr != target.FRPAdvertiseAddr || written.FRPServerPort != target.FRPBindPort {
		t.Fatalf("runtime settings were not persisted: %#v", written.Node)
	}
}
