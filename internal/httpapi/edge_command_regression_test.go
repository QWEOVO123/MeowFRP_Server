package httpapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"
	"frp-control-server/internal/edgestate"
	"frp-control-server/internal/security"
)

func TestDisconnectHandlerReplayTargetsOnlyOriginalRuntime(t *testing.T) {
	ctx := context.Background()
	state, err := edgestate.Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	payload, _ := json.Marshal(cluster.IdentitySnapshot{Revision: 1, NodeAccessEnforced: true, Users: []cluster.SnapshotUser{{ID: 7, Username: "alice", Role: "user", Status: "active"}}, Tokens: []cluster.SnapshotToken{{ID: 9, UserID: 7, TokenHash: security.TokenHash("ak_test"), Status: "active"}}})
	if err := state.ApplyIdentitySnapshot(ctx, payload); err != nil {
		t.Fatal(err)
	}
	_, _, client, err := state.Credential(ctx, security.TokenHash("ak_test"), "desktop", true)
	if err != nil {
		t.Fatal(err)
	}
	old := db.RuntimeLease{LeaseID: "old", UserID: 7, TokenID: 9, ClientID: "desktop", RuntimeTokenHash: "old-hash", Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	if err := state.CreateLease(ctx, old, nil); err != nil {
		t.Fatal(err)
	}
	command := cluster.NodeCommand{CommandID: "kick", Command: "disconnect_client", Payload: json.RawMessage(`{"token_id":9,"client_id":"desktop"}`)}
	if _, _, err := state.BeginCommand(ctx, command); err != nil {
		t.Fatal(err)
	}
	if _, err := state.DisconnectClientForCommand(ctx, "kick", 9, "desktop", ""); err != nil {
		t.Fatal(err)
	}
	queued, err := state.PopClientCommands(ctx, client.ID)
	if err != nil || len(queued) != 1 {
		t.Fatalf("initial reauth=%#v %v", queued, err)
	}
	if err := state.AcknowledgeClientCommand(ctx, queued[0]["id"].(int64), client.ID); err != nil {
		t.Fatal(err)
	}
	fresh := old
	fresh.LeaseID = "fresh"
	fresh.RuntimeTokenHash = "fresh-hash"
	if err := state.CreateLease(ctx, fresh, nil); err != nil {
		t.Fatal(err)
	}
	s := NewServer(config.Config{Mode: config.ModeEdge, Edge: config.EdgeConfig{RemoteCommands: config.EdgeRemoteCommandsConfig{DisconnectClient: true}}}, nil, WithEdgeRuntime(state, nil))
	t.Cleanup(func() { _ = s.core.Close() })
	s.core.RememberRuntimeLease(old)
	s.core.RememberRuntimeLease(fresh)
	result := s.HandleEdgeCommand(ctx, command)
	if result.Status != "succeeded" {
		t.Fatalf("recovery failed: %#v", result)
	}
	if _, ok := s.core.ExistingRuntime("fresh", "fresh-hash"); !ok {
		t.Fatal("handler revoked relogged client's runtime")
	}
	if _, ok := s.core.ExistingRuntime("old", "old-hash"); ok {
		t.Fatal("handler left original runtime authorized")
	}
	if commands, err := state.PopClientCommands(ctx, client.ID); err != nil || len(commands) != 0 {
		t.Fatalf("handler duplicated reauth: %#v %v", commands, err)
	}
}

func TestDPIReportingConfigChangeGatesEnqueueAndPrunesOldEvents(t *testing.T) {
	ctx := context.Background()
	state, err := edgestate.Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	cfg := config.Config{Mode: config.ModeEdge}
	s := NewServer(cfg, nil, WithEdgeRuntime(state, nil))
	t.Cleanup(func() { _ = s.core.Close() })
	state.RecordDPIEvent(ctx, dpi.Event{})
	if got, err := state.PendingEvents(ctx); err != nil || len(got) != 0 {
		t.Fatalf("disabled configuration queued event: %#v %v", got, err)
	}
	cfg.Edge.Reporting.DPIEvents = true
	s.setRuntime(cfg, nil)
	state.RecordDPIEvent(ctx, dpi.Event{})
	if got, err := s.EdgePendingEvents(ctx); err != nil || len(got) != 1 {
		t.Fatalf("enabled configuration lost event: %#v %v", got, err)
	}
	cfg.Edge.Reporting.DPIEvents = false
	s.setRuntime(cfg, nil)
	if got, err := state.PendingEvents(ctx); err != nil || len(got) != 0 {
		t.Fatalf("disabled configuration kept backlog: %#v %v", got, err)
	}
}
