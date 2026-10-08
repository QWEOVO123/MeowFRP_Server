package cluster

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"frp-control-server/internal/db"
)

// Identity-cache operations are not the subject of these wire payload tests.
type blacklistSyncStore struct {
	memoryNodeStore
	blocks   []db.BlockedInboundIP
	revision int64
	resets   int
}

func (s *blacklistSyncStore) ListBlockedInboundIPs(context.Context) ([]db.BlockedInboundIP, error) {
	return s.blocks, nil
}
func (s *blacklistSyncStore) ReadNodeIdentityPage(context.Context, string, int64, []int64, int) (*db.NodeIdentityPage, error) {
	return &db.NodeIdentityPage{End: true}, nil
}
func (s *blacklistSyncStore) NextIdentityRevision(context.Context) (int64, error) {
	s.revision++
	return s.revision, nil
}
func (s *blacklistSyncStore) ResetNodeIdentityCache(context.Context, string, string, string) error {
	s.resets++
	return nil
}
func (s *blacklistSyncStore) MarkUserIdentityDirty(context.Context, int64) error { return nil }
func (s *blacklistSyncStore) PendingNodeIdentityUsers(context.Context, string, string) ([]int64, error) {
	return nil, nil
}
func (s *blacklistSyncStore) PrepareNodeIdentityCache(context.Context, string, string, int64, []int64) error {
	return nil
}
func (s *blacklistSyncStore) ConfirmNodeIdentityCache(context.Context, string, string, int64, []int64, []int64, bool) error {
	return nil
}

func decodeBlacklist(t *testing.T, message *Message, err error) IdentitySnapshot {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot IdentitySnapshot
	if err := json.Unmarshal(message.Payload, &snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestGlobalBlacklistSchedulesEveryEdgeAndSendsDelta(t *testing.T) {
	now := time.Now()
	unchanged := db.BlockedInboundIP{IP: "192.0.2.1", Reason: "unchanged", CreatedAt: now}
	added := db.BlockedInboundIP{IP: "192.0.2.2", Reason: "new", CreatedAt: now}
	store := &blacklistSyncStore{blocks: []db.BlockedInboundIP{unchanged, added}}
	s := NewControllerServer(store, PKIPaths{})
	for _, id := range []string{"edge-a", "edge-b"} {
		s.sessions[id] = &nodeSession{nodeID: id, cacheProtocol: 3, admissionProtocol: 1, blockedIPs: map[string]db.BlockedInboundIP{unchanged.IP: unchanged, "192.0.2.3": {IP: "192.0.2.3"}}}
	}
	s.ScheduleBlockedIPPush()
	for id, session := range s.sessions {
		if !session.needsBlockedIPs || session.needsFull {
			t.Fatalf("%s did not schedule incremental blacklist push", id)
		}
		message, err := s.blockedIPMessage(context.Background(), session)
		snapshot := decodeBlacklist(t, message, err)
		if !snapshot.Incremental || snapshot.ReplaceBlockedIPs || len(snapshot.BlockedIPs) != 1 || snapshot.BlockedIPs[0].IP != added.IP || len(snapshot.RemovedBlockedIPs) != 1 || snapshot.RemovedBlockedIPs[0] != "192.0.2.3" {
			t.Fatalf("wrong delta for %s: %#v", id, snapshot)
		}
	}
}

func TestEdgeReconnectBaselineContainsFullCurrentBlacklist(t *testing.T) {
	store := &blacklistSyncStore{blocks: []db.BlockedInboundIP{{IP: "192.0.2.1", CreatedAt: time.Now()}, {IP: "192.0.2.2", CreatedAt: time.Now()}}}
	s := NewControllerServer(store, PKIPaths{})
	session := &nodeSession{nodeID: "edge", cacheProtocol: 3, cacheSessionID: "epoch", bootID: "boot", cacheReady: false, blockedIPs: map[string]db.BlockedInboundIP{"stale": {IP: "stale"}}}
	s.sessions[session.nodeID] = session
	if err := s.acceptCacheCleared(context.Background(), session, Message{CacheSessionID: "epoch"}); err != nil {
		t.Fatal(err)
	}
	if store.resets != 1 || len(session.blockedIPs) != 0 || !session.baselineActive {
		t.Fatal("reconnect did not reset controller's cached blacklist knowledge")
	}
	message, err := s.identityPageMessage(context.Background(), session, nil)
	snapshot := decodeBlacklist(t, message, err)
	if !snapshot.BaselineEnd || !snapshot.ReplaceBlockedIPs || len(snapshot.BlockedIPs) != 2 {
		t.Fatalf("baseline omitted full blacklist: %#v", snapshot)
	}
	// The empty list must also be explicit, so removed bans cannot survive a reconnect.
	store.blocks = nil
	message, err = s.identityPageMessage(context.Background(), session, nil)
	snapshot = decodeBlacklist(t, message, err)
	if !snapshot.ReplaceBlockedIPs || len(snapshot.BlockedIPs) != 0 {
		t.Fatalf("empty baseline not authoritative: %#v", snapshot)
	}
}
