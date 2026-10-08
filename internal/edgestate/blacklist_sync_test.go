package edgestate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/db"
)

func TestGlobalBlacklistDeltaAndReconnectFullReplacement(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "edge.data")
	s, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	apply := func(snapshot cluster.IdentitySnapshot) {
		t.Helper()
		payload, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ApplyIdentitySnapshot(ctx, payload); err != nil {
			t.Fatal(err)
		}
	}
	assertIPs := func(want ...string) {
		t.Helper()
		blocks, err := s.ListBlockedIPs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, block := range blocks {
			got[block.IP] = true
		}
		if len(got) != len(want) {
			t.Fatalf("blacklist=%#v want=%#v", got, want)
		}
		for _, ip := range want {
			if !got[ip] {
				t.Fatalf("missing ban %s: %#v", ip, got)
			}
		}
	}
	block := func(ip string) db.BlockedInboundIP {
		return db.BlockedInboundIP{IP: ip, Reason: "global", CreatedAt: time.Now()}
	}
	if err := s.UpsertBlockedIP(ctx, "192.0.2.99", "local ban"); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetIdentityCache(ctx); err != nil {
		t.Fatal(err)
	}
	apply(cluster.IdentitySnapshot{Revision: 1, Baseline: true, BaselineEnd: true, ReplaceBlockedIPs: true, BlockedIPs: []db.BlockedInboundIP{block("192.0.2.1")}})
	apply(cluster.IdentitySnapshot{Revision: 2, Incremental: true, BlockedIPs: []db.BlockedInboundIP{block("192.0.2.2")}})
	assertIPs("192.0.2.1", "192.0.2.2", "192.0.2.99")
	// Persistent global cache survives normal open/close, until explicit reset.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(file)
	if err != nil {
		t.Fatal(err)
	}
	assertIPs("192.0.2.1", "192.0.2.2", "192.0.2.99")
	apply(cluster.IdentitySnapshot{Revision: 3, Incremental: true, RemovedBlockedIPs: []string{"192.0.2.1"}})
	assertIPs("192.0.2.2", "192.0.2.99")
	if err := s.DiscardControlIdentityCache(ctx); err != nil {
		t.Fatal(err)
	}
	assertIPs("192.0.2.99")
	// Latest authoritative list, not the stale list from before disconnect.
	apply(cluster.IdentitySnapshot{Revision: 4, Baseline: true, BaselineEnd: true, ReplaceBlockedIPs: true, BlockedIPs: []db.BlockedInboundIP{block("192.0.2.3")}})
	assertIPs("192.0.2.3", "192.0.2.99")
	if err := s.DiscardControlIdentityCache(ctx); err != nil {
		t.Fatal(err)
	}
	apply(cluster.IdentitySnapshot{Revision: 5, Baseline: true, BaselineEnd: true, ReplaceBlockedIPs: true})
	assertIPs("192.0.2.99")
}
