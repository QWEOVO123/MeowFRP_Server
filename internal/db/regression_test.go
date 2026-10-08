package db

import (
	"context"
	"database/sql"
	"testing"

	"frp-control-server/internal/dpi"
	_ "modernc.org/sqlite"
)

func TestNormalizeDPIPolicyPreservesExplicitEmptyDetectors(t *testing.T) {
	if got := normalizeDPIPolicy(dpi.Policy{EnabledDetectors: []string{}}); got.EnabledDetectors == nil || len(got.EnabledDetectors) != 0 {
		t.Fatalf("explicit empty selection restored defaults: %#v", got)
	}
	if got := normalizeDPIPolicy(dpi.Policy{}); len(got.EnabledDetectors) != 4 {
		t.Fatalf("missing detector setting lost default: %#v", got)
	}
}

func TestCompletedConfigurationRevisionIgnoresMalformedHistoricalJSON(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	if _, err := database.Exec(`CREATE TABLE node_commands(node_id TEXT,command_type TEXT,status TEXT,payload_json TEXT)`); err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{`not-json`, `{"_configuration_revision":7}`, `{"_configuration_revision":"invalid"}`, `{"_configuration_revision":2}`, `{"_configuration_revision":`, `null`} {
		if _, err := database.Exec(`INSERT INTO node_commands VALUES('node','update_edge_runtime_settings','succeeded',?)`, payload); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`INSERT INTO node_commands VALUES('other','update_edge_runtime_settings','succeeded','{"_configuration_revision":999}')`); err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	got, err := greatestCompletedConfigurationRevision(context.Background(), tx, "node")
	if err != nil || got != 7 {
		t.Fatalf("revision=%d err=%v", got, err)
	}
}

func TestIdentityPageRejectsOversizedDirtyBatchBeforeDatabaseAccess(t *testing.T) {
	store := &Store{}
	if _, err := store.ReadNodeIdentityPage(context.Background(), "node", 0, make([]int64, 65), 64); err == nil {
		t.Fatal("oversized dirty batch can incorrectly classify users as removed")
	}
}
