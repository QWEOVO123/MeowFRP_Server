package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"frp-control-server/internal/db"
	"log"
	"time"
)

// API writes, snapshot reads and ACKs share a lock to avoid torn identity data.
func (s *ControllerServer) LockIdentityMutation() func() {
	s.syncMu.Lock()
	return s.syncMu.Unlock
}

func (s *ControllerServer) wakeIdentityPush() {
	select {
	case s.identityChanges <- struct{}{}:
	default:
	}
}

func (s *ControllerServer) ScheduleIdentityPush() {
	s.mu.Lock()
	for _, session := range s.sessions {
		session.needsFull = true
	}
	s.mu.Unlock()
	s.wakeIdentityPush()
}

func (s *ControllerServer) ScheduleBlockedIPPush() {
	s.mu.Lock()
	for _, session := range s.sessions {
		if session.cacheProtocol >= 3 {
			session.needsBlockedIPs = true
		} else {
			session.needsFull = true
		}
	}
	s.mu.Unlock()
	s.wakeIdentityPush()
}

// Mutators commit the dirty index atomically with their business SQL; the HTTP
// layer only wakes the delivery worker, so a lost wakeup cannot lose a change.
func (s *ControllerServer) NotifyUserIdentityChanged(userID int64) {
	if _, ok := s.store.(IdentityCacheStore); !ok {
		s.ScheduleIdentityPush()
		return
	}
	log.Printf("identity user changed: user=%d durable update queued", userID)
	s.wakeIdentityPush()
}

// Caller holds LockIdentityMutation. Offline/missed wakeups stay dirty in SQL.
func (s *ControllerServer) ScheduleUserIdentityPush(ctx context.Context, userID int64) error {
	cache, ok := s.store.(IdentityCacheStore)
	if !ok {
		s.ScheduleIdentityPush()
		return nil
	}
	if err := cache.MarkUserIdentityDirty(ctx, userID); err != nil {
		s.ScheduleIdentityPush()
		return err
	}
	log.Printf("identity user changed: user=%d queued cache owners and authorized nodes", userID)
	s.wakeIdentityPush()
	return nil
}

func (s *ControllerServer) runIdentityPushes(ctx context.Context) {
	// Local retry of dirty metadata only. No policy/telemetry polling of edges.
	retry := time.NewTicker(2 * time.Second)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.identityChanges:
		case <-retry.C:
		}
		s.pushPendingIdentities(ctx)
		if !s.DatabaseUnavailable() {
			for _, id := range s.ConnectedNodes() {
				s.dispatchPendingCommands(ctx, id)
			}
		}
	}
}

func (s *ControllerServer) PushIdentities(ctx context.Context) {
	s.ScheduleIdentityPush()
	s.pushPendingIdentities(ctx)
}

func (s *ControllerServer) pushPendingIdentities(ctx context.Context) {
	for _, nodeID := range s.ConnectedNodes() {
		if ctx.Err() != nil {
			return
		}
		s.pushNodeIdentity(ctx, nodeID)
	}
}

func (s *ControllerServer) pushNodeIdentity(ctx context.Context, nodeID string) {
	if s.DatabaseUnavailable() {
		return
	}
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	s.mu.RLock()
	session := s.sessions[nodeID]
	if session == nil || session.cacheSessionID == "" || session.pendingRevision > session.appliedRevision {
		s.mu.RUnlock()
		return
	}
	full := session.needsFull
	baseline := session.baselineActive
	blocked := session.needsBlockedIPs
	ready := session.cacheReady
	s.mu.RUnlock()
	if full && !ready && session.cacheProtocol >= 3 {
		if err := s.requestCacheReset(session); err != nil {
			session.cancel()
		}
		return
	}
	if !ready {
		return
	}
	if full && !baseline && session.cacheProtocol >= 3 {
		if err := s.requestCacheReset(session); err != nil {
			session.cancel()
		}
		return
	}
	if blocked && !full && !baseline && session.cacheProtocol >= 3 {
		message, err := s.blockedIPMessage(ctx, session)
		if err == nil {
			err = s.enqueueIdentity(ctx, session, message)
		}
		if err != nil {
			log.Printf("blocked IP push node=%s: %v", nodeID, err)
			s.mu.Lock()
			session.needsBlockedIPs = true
			s.mu.Unlock()
		}
		return
	}
	var users []int64
	if !full && !baseline {
		cache, ok := s.store.(IdentityCacheStore)
		if !ok {
			return
		}
		var err error
		users, err = cache.PendingNodeIdentityUsers(ctx, nodeID, session.cacheSessionID)
		if err != nil {
			log.Printf("identity pending lookup node=%s: %v", nodeID, err)
			return
		}
		if len(users) == 0 {
			return
		}
		if session.cacheProtocol < 2 {
			full = true
			users = nil
		}
	}
	var message *Message
	var err error
	if session.cacheProtocol >= 3 {
		message, err = s.identityPageMessage(ctx, session, users)
	} else {
		message, err = s.identitySnapshotForUsers(ctx, nodeID, users)
	}
	if err == nil && message != nil {
		err = s.enqueueIdentity(ctx, session, message)
	}
	if err != nil {
		log.Printf("identity push node=%s: %v", nodeID, err)
	}
}

// syncMu held. The ACK can only acknowledge this exact prepared snapshot.
func (s *ControllerServer) enqueueIdentity(ctx context.Context, session *nodeSession, message *Message) error {
	var snapshot IdentitySnapshot
	if err := json.Unmarshal(message.Payload, &snapshot); err != nil {
		return err
	}
	ids := append([]int64(nil), snapshot.RemovedUserIDs...)
	for _, user := range snapshot.Users {
		ids = append(ids, user.ID)
	}
	if cache, ok := s.store.(IdentityCacheStore); ok {
		if err := cache.PrepareNodeIdentityCache(ctx, session.nodeID, session.cacheSessionID, message.Revision, ids); err != nil {
			return err
		}
	}
	message.CacheSessionID = session.cacheSessionID
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[session.nodeID] != session {
		return fmt.Errorf("superseded edge session")
	}
	session.pendingRevision = message.Revision
	session.pendingIdentity = &snapshot
	session.syncStarted = time.Now()
	session.applyProgress = 0
	if !snapshot.Incremental && !snapshot.Baseline {
		session.needsFull = false
	}
	if session.cacheProtocol >= 3 {
		session.pendingPayload = message.Payload
		session.chunkIndex = 0
		session.chunkTotal = (len(message.Payload) + identityChunkBytes - 1) / identityChunkBytes
		log.Printf("identity paged push node=%s revision=%d baseline=%t end=%t users=%d removed=%d fragments=%d bytes=%d awaiting ACK", session.nodeID, message.Revision, snapshot.Baseline, snapshot.BaselineEnd, len(snapshot.Users), len(snapshot.RemovedUserIDs), session.chunkTotal, len(message.Payload))
		return s.sendIdentityChunkLocked(session)
	}
	select {
	case session.send <- *message:
		log.Printf("identity push node=%s revision=%d incremental=%t users=%d removed=%d awaiting ACK", session.nodeID, message.Revision, snapshot.Incremental, len(snapshot.Users), len(snapshot.RemovedUserIDs))
		return nil
	default:
		return fmt.Errorf("edge identity send queue full")
	}
}

func (s *ControllerServer) confirmIdentity(ctx context.Context, session *nodeSession, message Message) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	s.mu.RLock()
	current := s.sessions[session.nodeID] == session
	epoch := session.cacheSessionID
	snapshot := session.pendingIdentity
	applied := session.appliedRevision
	chunksComplete := session.chunkIndex == session.chunkTotal
	s.mu.RUnlock()
	if !current {
		return fmt.Errorf("superseded cache acknowledgement")
	}
	if session.cacheProtocol >= 2 && message.CacheSessionID != epoch {
		return nil
	}
	if message.Revision <= applied {
		return nil
	}
	if snapshot == nil || snapshot.Revision != message.Revision {
		return fmt.Errorf("unexpected identity acknowledgement revision")
	}
	if session.cacheProtocol >= 3 && !chunksComplete {
		return fmt.Errorf("identity ACK before all fragments received")
	}
	if session.cacheProtocol >= 2 && message.CacheSessionID != session.cacheSessionID {
		return fmt.Errorf("identity ACK cache session mismatch")
	}
	ids := make([]int64, 0, len(snapshot.Users))
	for _, user := range snapshot.Users {
		ids = append(ids, user.ID)
	}
	if cache, ok := s.store.(IdentityCacheStore); ok {
		if err := cache.ConfirmNodeIdentityCache(ctx, session.nodeID, session.cacheSessionID, message.Revision, ids, snapshot.RemovedUserIDs, !snapshot.Incremental && !snapshot.Baseline); err != nil {
			return identityStorageError{err}
		}
	}
	s.mu.Lock()
	session.appliedRevision = message.Revision
	session.pendingIdentity = nil
	session.pendingPayload = nil
	if snapshot.ReplaceBlockedIPs {
		session.blockedIPs = map[string]db.BlockedInboundIP{}
	}
	if session.blockedIPs == nil {
		session.blockedIPs = map[string]db.BlockedInboundIP{}
	}
	for _, block := range snapshot.BlockedIPs {
		session.blockedIPs[block.IP] = block
	}
	for _, ip := range snapshot.RemovedBlockedIPs {
		delete(session.blockedIPs, ip)
	}
	if snapshot.Baseline {
		session.baselineCursor = session.pendingCursor
		session.baselineActive = !snapshot.BaselineEnd
	}
	s.mu.Unlock()
	if session.cacheProtocol >= 2 {
		select {
		case session.send <- Message{Type: "identity_confirmed", NodeID: session.nodeID, Revision: message.Revision, CacheSessionID: session.cacheSessionID, SyncComplete: !snapshot.Baseline || snapshot.BaselineEnd, SentAt: time.Now()}:
		default:
			return fmt.Errorf("edge identity confirmation queue full")
		}
	}
	log.Printf("identity applied node=%s revision=%d users=%d removed=%d", session.nodeID, message.Revision, len(ids), len(snapshot.RemovedUserIDs))
	s.wakeIdentityPush()
	return nil
}
