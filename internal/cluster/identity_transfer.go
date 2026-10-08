package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"frp-control-server/internal/db"
	"frp-control-server/internal/security"
)

type identityPageStore interface {
	ReadNodeIdentityPage(context.Context, string, int64, []int64, int) (*db.NodeIdentityPage, error)
	ListBlockedInboundIPs(context.Context) ([]db.BlockedInboundIP, error)
}

func (s *ControllerServer) blockedIPMessage(ctx context.Context, session *nodeSession) (*Message, error) {
	store, ok := s.store.(identityPageStore)
	if !ok {
		return nil, errors.New("blocked IP store unavailable")
	}
	blocks, err := store.ListBlockedInboundIPs(ctx)
	if err != nil {
		return nil, err
	}
	cache, ok := s.store.(IdentityCacheStore)
	if !ok {
		return nil, errors.New("identity revision store unavailable")
	}
	revision, err := cache.NextIdentityRevision(ctx)
	if err != nil {
		return nil, err
	}
	snapshot := IdentitySnapshot{Revision: revision, Incremental: true, NodeAccessEnforced: true}
	wanted := map[string]bool{}
	s.mu.RLock()
	for _, block := range blocks {
		wanted[block.IP] = true
		old, known := session.blockedIPs[block.IP]
		if !known || old.Reason != block.Reason || !old.CreatedAt.Equal(block.CreatedAt) {
			snapshot.BlockedIPs = append(snapshot.BlockedIPs, block)
		}
	}
	for ip := range session.blockedIPs {
		if !wanted[ip] {
			snapshot.RemovedBlockedIPs = append(snapshot.RemovedBlockedIPs, ip)
		}
	}
	s.mu.RUnlock()
	if session.admissionProtocol < 1 {
		snapshot.ReplaceBlockedIPs = true
		snapshot.BlockedIPs = blocks
		snapshot.RemovedBlockedIPs = nil
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	session.needsBlockedIPs = false
	s.mu.Unlock()
	return &Message{Type: "identity_snapshot", NodeID: session.nodeID, Revision: revision, Payload: payload, SentAt: time.Now()}, nil
}

// syncMu is held. A fresh epoch also fences ACKs from a previous full refresh.
func (s *ControllerServer) requestCacheReset(session *nodeSession) error {
	id, _, err := security.NewOpaqueToken("cache_")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[session.nodeID] != session {
		return errors.New("superseded cache reset")
	}
	session.cacheSessionID = id
	session.cacheReady = false
	session.needsFull = false
	session.syncStarted = time.Now()
	payload, _ := json.Marshal(HeartbeatAck{ControllerFault: s.databaseFault, IdentityProtocol: 3, IntervalSeconds: s.heartbeatInterval, ServerTime: time.Now()})
	select {
	case session.send <- Message{Type: "welcome", NodeID: session.nodeID, CacheSessionID: id, Payload: payload, SentAt: time.Now()}:
		return nil
	default:
		return errors.New("cache reset send queue full")
	}
}

func (s *ControllerServer) acceptCacheCleared(ctx context.Context, session *nodeSession, message Message) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	s.mu.RLock()
	valid := s.sessions[session.nodeID] == session && session.cacheProtocol >= 3 && message.CacheSessionID == session.cacheSessionID
	ready := session.cacheReady
	s.mu.RUnlock()
	if !valid {
		if message.CacheSessionID != session.cacheSessionID {
			return nil
		}
		return errors.New("cache-cleared session mismatch")
	}
	if ready {
		return nil
	}
	cache, ok := s.store.(IdentityCacheStore)
	if !ok {
		return errors.New("durable identity cache store unavailable")
	}
	if err := cache.ResetNodeIdentityCache(ctx, session.nodeID, session.cacheSessionID, session.bootID); err != nil {
		return identityStorageError{err}
	}
	s.mu.Lock()
	session.cacheReady = true
	session.needsFull = false
	session.baselineActive = true
	session.baselineCursor = 0
	session.pendingRevision = 0
	session.appliedRevision = 0
	session.pendingIdentity = nil
	session.blockedIPs = map[string]db.BlockedInboundIP{}
	session.syncStarted = time.Now()
	s.mu.Unlock()
	log.Printf("edge cache cleared node=%s session=%s; center associations reset after edge commit", session.nodeID, session.cacheSessionID)
	s.wakeIdentityPush()
	return nil
}

// syncMu is held only while reading/preparing a page, never during transmission.
func (s *ControllerServer) identityPageMessage(ctx context.Context, session *nodeSession, users []int64) (*Message, error) {
	store, ok := s.store.(identityPageStore)
	if !ok {
		return nil, errors.New("paged identity store unavailable")
	}
	s.mu.RLock()
	baseline, cursor := session.baselineActive, session.baselineCursor
	s.mu.RUnlock()
	if !baseline {
		cursor = 0
	}
	page, err := store.ReadNodeIdentityPage(ctx, session.nodeID, cursor, users, 64)
	if err != nil {
		return nil, err
	}
	cache := s.store.(IdentityCacheStore)
	revision, err := cache.NextIdentityRevision(ctx)
	if err != nil {
		return nil, err
	}
	snapshot := IdentitySnapshot{Revision: revision, NodeAccessEnforced: true, Incremental: !baseline, Baseline: baseline, BaselineEnd: baseline && page.End, RemovedUserIDs: page.Removed, Policies: page.Policies, Grants: page.Grants, DPIPolicies: page.DPIPolicies}
	for _, u := range page.Users {
		snapshot.Users = append(snapshot.Users, SnapshotUser{u.ID, u.Username, u.Role, u.Status, u.BanReason})
	}
	for _, t := range page.Tokens {
		snapshot.Tokens = append(snapshot.Tokens, SnapshotToken{t.ID, t.UserID, t.Name, t.TokenHash, t.Status, t.BanReason, t.MaxProxyCount, t.ExpiresAt})
	}
	if snapshot.BaselineEnd {
		snapshot.ReplaceBlockedIPs = true
		snapshot.BlockedIPs, err = store.ListBlockedInboundIPs(ctx)
		if err != nil {
			return nil, err
		}
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	session.pendingCursor = page.LastID
	s.mu.Unlock()
	return &Message{Type: "identity_snapshot", NodeID: session.nodeID, Revision: revision, Payload: payload, SentAt: time.Now()}, nil
}

// mu is held. At most one unacknowledged wire fragment per node.
func (s *ControllerServer) sendIdentityChunkLocked(session *nodeSession) error {
	start := session.chunkIndex * identityChunkBytes
	end := start + identityChunkBytes
	if end > len(session.pendingPayload) {
		end = len(session.pendingPayload)
	}
	chunk := IdentityChunk{Index: session.chunkIndex, Total: session.chunkTotal, Data: session.pendingPayload[start:end]}
	payload, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	select {
	case session.send <- Message{Type: "identity_chunk", NodeID: session.nodeID, Revision: session.pendingRevision, Sequence: int64(session.chunkIndex), CacheSessionID: session.cacheSessionID, Payload: payload, SentAt: time.Now()}:
		return nil
	default:
		return errors.New("identity fragment send queue full")
	}
}

func (s *ControllerServer) acceptIdentityProgress(session *nodeSession, message Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[session.nodeID] == session && message.CacheSessionID != session.cacheSessionID {
		return nil
	}
	if message.CacheSessionID == session.cacheSessionID && message.Revision <= session.appliedRevision {
		return nil
	}
	if s.sessions[session.nodeID] != session || session.cacheProtocol < 3 || message.CacheSessionID != session.cacheSessionID || session.pendingIdentity == nil || message.Revision != session.pendingRevision {
		return errors.New("identity progress epoch/revision mismatch")
	}
	if message.Type == "identity_progress" {
		if message.Sequence > session.applyProgress {
			session.applyProgress = message.Sequence
			session.syncStarted = time.Now()
		}
		return nil
	}
	if message.Sequence < int64(session.chunkIndex) {
		return nil
	}
	if message.Sequence != int64(session.chunkIndex) || session.chunkIndex >= session.chunkTotal {
		return fmt.Errorf("unexpected identity chunk acknowledgement %d", message.Sequence)
	}
	session.syncStarted = time.Now()
	session.chunkIndex++
	if session.chunkIndex < session.chunkTotal {
		return s.sendIdentityChunkLocked(session)
	}
	return nil
}
