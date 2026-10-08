package edgestate

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"
	"frp-control-server/internal/security"
)

func TestDPIEventReportingSwitchStopsQueueAndClearsBacklog(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	enabled := false
	s.SetDPIEventReporting(func() bool { return enabled })
	s.RecordDPIEvent(ctx, dpi.Event{})
	if got, err := s.PendingEvents(ctx); err != nil || len(got) != 0 {
		t.Fatalf("disabled queue=%#v err=%v", got, err)
	}
	enabled = true
	s.RecordDPIEvent(ctx, dpi.Event{})
	if got, err := s.PendingEvents(ctx); err != nil || len(got) != 1 {
		t.Fatalf("enabled queue=%#v err=%v", got, err)
	}
	enabled = false
	if err := s.PruneDisabledDPIEvents(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PendingEvents(ctx); err != nil || len(got) != 0 {
		t.Fatalf("disabled backlog=%#v err=%v", got, err)
	}
}

func TestDPIEventQueueIsBoundedAndRetainsNewest(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxQueuedTelemetryEvents+3; i++ {
		if _, err := tx.ExecContext(ctx, `INSERT INTO outbound_events(event_id,event_type,payload) VALUES(?,'dpi_event','{}')`, fmt.Sprintf("event-%d", i)); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "newest", "dpi_event", map[string]bool{"ok": true}); err != nil {
		t.Fatal(err)
	}
	var count, oldest, newest int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),MIN(id),MAX(id) FROM outbound_events WHERE event_type='dpi_event'`).Scan(&count, &oldest, &newest); err != nil {
		t.Fatal(err)
	}
	if count != maxQueuedTelemetryEvents || oldest != 5 || newest != maxQueuedTelemetryEvents+4 {
		t.Fatalf("count=%d oldest=%d newest=%d", count, oldest, newest)
	}
}

func TestDisconnectCommandCrashReplayDoesNotKickReloggedClient(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "edge.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	snapshot := cluster.IdentitySnapshot{Revision: 1, NodeAccessEnforced: true, Users: []cluster.SnapshotUser{{ID: 7, Username: "alice", Role: "user", Status: "active"}}, Tokens: []cluster.SnapshotToken{{ID: 9, UserID: 7, TokenHash: security.TokenHash("ak_test"), Status: "active"}}}
	payload, _ := json.Marshal(snapshot)
	if err := s.ApplyIdentitySnapshot(ctx, payload); err != nil {
		t.Fatal(err)
	}
	_, _, client, err := s.Credential(ctx, security.TokenHash("ak_test"), "desktop", true)
	if err != nil {
		t.Fatal(err)
	}
	old := db.RuntimeLease{LeaseID: "old", UserID: 7, TokenID: 9, ClientID: "desktop", RuntimeTokenHash: "old-hash", Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateLease(ctx, old, nil); err != nil {
		t.Fatal(err)
	}
	command := cluster.NodeCommand{CommandID: "disconnect", Command: "disconnect_client", Payload: json.RawMessage(`{"token_id":9,"client_id":"desktop"}`)}
	if _, _, err := s.BeginCommand(ctx, command); err != nil {
		t.Fatal(err)
	}
	ids, err := s.DisconnectClientForCommand(ctx, command.CommandID, 9, "desktop", "reason")
	if err != nil || len(ids) != 1 || ids[0] != "old" {
		t.Fatalf("first effect=%#v err=%v", ids, err)
	}
	queued, err := s.PopClientCommands(ctx, client.ID)
	if err != nil || len(queued) != 1 {
		t.Fatalf("reauth=%#v err=%v", queued, err)
	}
	if err := s.AcknowledgeClientCommand(ctx, queued[0]["id"].(int64), client.ID); err != nil {
		t.Fatal(err)
	}
	// Simulate process exit after side effects but before FinishCommand.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	newLease := old
	newLease.LeaseID = "new"
	newLease.RuntimeTokenHash = "new-hash"
	if err := s.CreateLease(ctx, newLease, nil); err != nil {
		t.Fatal(err)
	}
	execute, _, err := s.BeginCommand(ctx, command)
	if err != nil || !execute {
		t.Fatalf("unfinished command cannot recover: execute=%t err=%v", execute, err)
	}
	ids, err = s.DisconnectClientForCommand(ctx, command.CommandID, 9, "desktop", "reason")
	if err != nil || len(ids) != 1 || ids[0] != "old" {
		t.Fatalf("replay targeted fresh lease: %#v err=%v", ids, err)
	}
	if got, err := s.RuntimeLease(ctx, "new-hash"); err != nil || got.Status != "active" {
		t.Fatalf("relogin revoked: %#v err=%v", got, err)
	}
	if got, err := s.PopClientCommands(ctx, client.ID); err != nil || len(got) != 0 {
		t.Fatalf("duplicate reauth=%#v err=%v", got, err)
	}
}

func TestDisconnectEffectRollsBackOnQueueInsertFailure(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`INSERT INTO edge_clients(user_id,token_id,client_id) VALUES(7,9,'desktop'); CREATE TRIGGER fail_reauth BEFORE INSERT ON edge_client_commands BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO cached_tokens(id,user_id,name,token_hash,status,max_proxy_count) VALUES(9,7,'desktop','ak_hash','active',1)`); err != nil {
		t.Fatal(err)
	}
	lease := db.RuntimeLease{LeaseID: "active", UserID: 7, TokenID: 9, ClientID: "desktop", RuntimeTokenHash: "hash", Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateLease(ctx, lease, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DisconnectClientForCommand(ctx, "cmd", 9, "desktop", "reason"); err == nil {
		t.Fatal("injected queue error not propagated")
	}
	if got, err := s.RuntimeLease(ctx, "hash"); err != nil || got.Status != "active" {
		t.Fatalf("partial revocation committed: %#v err=%v", got, err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM command_disconnect_effects`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("effect falsely committed: %d %v", count, err)
	}
}

func TestIdentityResetDoesNotEraseCommandDeduplication(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO command_disconnect_effects VALUES('cmd','["old"]')`); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetIdentityCache(ctx); err != nil {
		t.Fatal(err)
	}
	ids, err := s.DisconnectClientForCommand(ctx, "cmd", 9, "desktop", "reason")
	if err != nil || len(ids) != 1 || ids[0] != "old" {
		t.Fatalf("cache reset lost effect marker: %#v %v", ids, err)
	}
}
