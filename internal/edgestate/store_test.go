package edgestate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"
	"frp-control-server/internal/dpiengine"
	"frp-control-server/internal/security"
)

func TestOpenAndQueueEvent(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.QueueEvent(context.Background(), "evt-1", "heartbeat", map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueEvent(context.Background(), "evt-1", "heartbeat", map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	status, err := store.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.PendingEvents != 1 {
		t.Fatalf("expected idempotent queued event, got %d", status.PendingEvents)
	}
}

func TestReliableEventsPoliciesAndScopedBlocks(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.QueueEvent(ctx, "evt-1", "dpi_event", map[string]any{"action": "block"}); err != nil {
		t.Fatal(err)
	}
	events, err := store.PendingEvents(ctx)
	if err != nil || len(events) != 1 || !json.Valid(events[0].Payload) {
		t.Fatalf("pending events=%#v err=%v", events, err)
	}
	if err := store.AcknowledgeEvents(ctx, []string{"evt-1"}); err != nil {
		t.Fatal(err)
	}
	if events, err = store.PendingEvents(ctx); err != nil || len(events) != 0 {
		t.Fatalf("acknowledged events must not be retried: %#v err=%v", events, err)
	}

	policy := dpi.DefaultPolicy()
	policy.UserID = 7
	policy.Enabled = true
	policy.Mode = dpi.ModeBlock
	snapshot := cluster.IdentitySnapshot{Revision: 1, DPIPolicies: []dpi.Policy{policy}, BlockedIPs: []db.BlockedInboundIP{{IP: "203.0.113.10", Reason: "global", CreatedAt: time.Now()}}}
	payload, _ := json.Marshal(snapshot)
	if err := store.ApplyIdentitySnapshot(ctx, payload); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertBlockedIP(ctx, "198.51.100.20", "node-only"); err != nil {
		t.Fatal(err)
	}
	resolved, err := store.GetPolicy(ctx, dpiengine.FlowContext{UserID: 7})
	if err != nil || !resolved.Enabled || resolved.Mode != dpi.ModeBlock {
		t.Fatalf("unexpected cached DPI policy: %#v err=%v", resolved, err)
	}
	direct, err := store.DPIPolicy(ctx, 7)
	if err != nil || !direct.Enabled || direct.Mode != dpi.ModeBlock {
		t.Fatalf("unexpected direct cached DPI policy: %#v err=%v", direct, err)
	}
	payload, _ = json.Marshal(cluster.IdentitySnapshot{Revision: 2, DPIPolicies: []dpi.Policy{policy}})
	if err := store.ApplyIdentitySnapshot(ctx, payload); err != nil {
		t.Fatal(err)
	}
	blocks, err := store.ListBlockedIPs(ctx)
	if err != nil || len(blocks) != 1 || blocks[0].IP != "198.51.100.20" {
		t.Fatalf("global snapshot must preserve node-only blocks: %#v err=%v", blocks, err)
	}
}

func TestCommandExecutionIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	command := cluster.NodeCommand{CommandID: "cmd-1", Command: "block_ip", Payload: json.RawMessage(`{"ip":"203.0.113.1"}`)}
	execute, cached, err := store.BeginCommand(ctx, command)
	if err != nil || !execute || cached != nil {
		t.Fatalf("first command: execute=%v cached=%#v err=%v", execute, cached, err)
	}
	want := cluster.CommandResult{CommandID: command.CommandID, Status: "succeeded", Result: json.RawMessage(`{"ok":true}`)}
	if err := store.FinishCommand(ctx, want); err != nil {
		t.Fatal(err)
	}
	execute, cached, err = store.BeginCommand(ctx, command)
	if err != nil || execute || cached == nil || cached.CommandID != command.CommandID || cached.Status != "succeeded" {
		t.Fatalf("duplicate command: execute=%v cached=%#v err=%v", execute, cached, err)
	}
}

func TestIdentitySnapshotSupportsDirectEdgeAuthentication(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	expires := time.Now().Add(time.Hour)
	snapshot := cluster.IdentitySnapshot{
		Revision:           42,
		NodeAccessEnforced: true,
		Users:              []cluster.SnapshotUser{{ID: 7, Username: "alice", Role: "user", Status: "active"}},
		Tokens:             []cluster.SnapshotToken{{ID: 9, UserID: 7, Name: "desktop", TokenHash: security.TokenHash("ak_secret"), Status: "active", MaxProxyCount: 2, ExpiresAt: &expires}},
		Policies:           []db.UserResourcePolicy{{UserID: 7, PortStart: 6000, PortEnd: 6010, MaxPorts: 2, AllowedProtocols: []string{"tcp"}, Enabled: true}},
	}
	payload, _ := json.Marshal(snapshot)
	if err := store.ApplyIdentitySnapshot(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	token, user, client, err := store.Credential(context.Background(), security.TokenHash("ak_secret"), "hwid-test", true)
	if err != nil {
		t.Fatal(err)
	}
	if token.ID != 9 || user.Username != "alice" || client.ClientID != "hwid-test" {
		t.Fatalf("unexpected cached identity: %#v %#v %#v", token, user, client)
	}
	if err := ValidateCredential(token, user, client); err != nil {
		t.Fatal(err)
	}
	show, err := store.DisconnectWarning(context.Background(), client.ID)
	if err != nil || !show {
		t.Fatalf("first disconnect warning: show=%v err=%v", show, err)
	}
	show, err = store.DisconnectWarning(context.Background(), client.ID)
	if err != nil || show {
		t.Fatalf("warning must be emitted once: show=%v err=%v", show, err)
	}
}

func TestClientCommandRetriesUntilAcknowledged(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot := cluster.IdentitySnapshot{
		Revision: 1,
		Users:    []cluster.SnapshotUser{{ID: 7, Username: "alice", Role: "user", Status: "active"}},
		Tokens:   []cluster.SnapshotToken{{ID: 9, UserID: 7, Name: "desktop", TokenHash: security.TokenHash("ak_secret"), Status: "active", MaxProxyCount: 1}},
	}
	payload, _ := json.Marshal(snapshot)
	if err := store.ApplyIdentitySnapshot(ctx, payload); err != nil {
		t.Fatal(err)
	}
	_, _, client, err := store.Credential(ctx, security.TokenHash("ak_secret"), "hwid-test", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueClientCommand(ctx, 9, "hwid-test", "show_warning", "hello"); err != nil {
		t.Fatal(err)
	}
	first, err := store.PopClientCommands(ctx, client.ID)
	if err != nil || len(first) != 1 {
		t.Fatalf("first delivery=%#v err=%v", first, err)
	}
	second, err := store.PopClientCommands(ctx, client.ID)
	if err != nil || len(second) != 1 || second[0]["id"] != first[0]["id"] {
		t.Fatalf("unacknowledged command must be retried: %#v err=%v", second, err)
	}
	commandID := first[0]["id"].(int64)
	if err := store.AcknowledgeClientCommand(ctx, commandID, client.ID); err != nil {
		t.Fatal(err)
	}
	afterACK, err := store.PopClientCommands(ctx, client.ID)
	if err != nil || len(afterACK) != 0 {
		t.Fatalf("acknowledged command must disappear: %#v err=%v", afterACK, err)
	}
}

func TestRuntimeLogWriterHonorsLocalReportingSwitch(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	enabled := false
	writer := NewRuntimeLogWriter(store, func() bool { return enabled })
	_, _ = writer.Write([]byte("disabled log\n"))
	if events, err := store.PendingEvents(ctx); err != nil || len(events) != 0 {
		t.Fatalf("disabled runtime logging queued events: %#v err=%v", events, err)
	}
	enabled = true
	_, _ = writer.Write([]byte("enabled log\n"))
	events, err := store.PendingEvents(ctx)
	if err != nil || len(events) != 1 || events[0].EventType != "runtime_log" || !strings.Contains(string(events[0].Payload), "enabled log") {
		t.Fatalf("runtime log event=%#v err=%v", events, err)
	}
}
