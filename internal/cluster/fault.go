package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"frp-control-server/internal/db"
	"time"
)

// All registered nodes, not only online sessions, remain available without SQL.
func (s *ControllerServer) ReplaceNodeCatalog(nodes []db.EdgeNode) {
	copy := make(map[string]db.EdgeNode, len(nodes))
	for _, node := range nodes {
		copy[node.NodeID] = node
	}
	s.mu.Lock()
	for id := range s.forgottenNodes {
		delete(copy, id)
	}
	s.nodeCatalog = copy
	s.mu.Unlock()
}
func (s *ControllerServer) NodeCatalog() []db.EdgeNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nodes := make([]db.EdgeNode, 0, len(s.nodeCatalog))
	for _, node := range s.nodeCatalog {
		nodes = append(nodes, node)
	}
	return nodes
}
func (s *ControllerServer) authorizedNode(ctx context.Context, id string) (*db.EdgeNode, error) {
	s.mu.RLock()
	cached, ok := s.nodeCatalog[id]
	suspect := s.databaseSuspect
	forgotten := s.forgottenNodes[id]
	s.mu.RUnlock()
	if forgotten {
		return nil, db.ErrNotFound
	}
	if suspect {
		if ok {
			return &cached, nil
		}
		return nil, db.ErrNotFound
	}
	readCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	node, err := s.store.GetEdgeNode(readCtx, id)
	if err == nil {
		s.mu.Lock()
		if s.forgottenNodes[id] {
			s.mu.Unlock()
			return nil, db.ErrNotFound
		}
		if s.nodeCatalog == nil {
			s.nodeCatalog = map[string]db.EdgeNode{}
		}
		s.nodeCatalog[id] = *node
		s.mu.Unlock()
		return node, nil
	}
	s.mu.RLock()
	cached, ok = s.nodeCatalog[id]
	suspect = s.databaseSuspect
	s.mu.RUnlock()
	// mTLS still validates CA/expiry, and the caller checks serial/status.
	// Never fall back on a normal not-found result (revocation/deletion).
	if suspect && ok && !errors.Is(err, db.ErrNotFound) {
		return &cached, nil
	}
	return nil, err
}
func (s *ControllerServer) DatabaseFault() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.databaseFault
}
func (s *ControllerServer) DatabaseUnavailable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.databaseSuspect
}
func (s *ControllerServer) SetDatabaseSuspect(suspect bool) {
	s.mu.Lock()
	s.databaseSuspect = suspect
	s.mu.Unlock()
}
func (s *ControllerServer) SetDatabaseFault(fault bool) {
	s.mu.Lock()
	wasFault := s.databaseFault
	s.databaseFault = fault
	if !fault {
		s.databaseSuspect = false
	}
	for id, session := range s.sessions {
		// Legacy edges cannot process admission notices; disconnecting fences
		// their new logins until a healthy baseline can be rebuilt. Upgrade all
		// edges to guarantee preservation of running tunnels during this fence.
		if fault && session.admissionProtocol < 1 {
			session.cancel()
			continue
		}
		session.syncStarted = time.Now()
		if !fault && (wasFault || !session.cacheReady) {
			session.needsFull = true
		}
		payload, _ := json.Marshal(HeartbeatAck{ControllerFault: fault, IntervalSeconds: s.heartbeatInterval, ServerTime: time.Now()})
		select {
		case session.send <- Message{Type: "controller_state", NodeID: id, Payload: payload, SentAt: time.Now()}:
		default:
			session.cancel()
		}
	}
	s.mu.Unlock()
	if !fault {
		s.wakeIdentityPush()
	}
}

type identityStorageError struct{ error }

func (s *ControllerServer) ForgetNode(id string) {
	s.mu.Lock()
	if s.forgottenNodes == nil {
		s.forgottenNodes = map[string]bool{}
	}
	s.forgottenNodes[id] = true
	delete(s.nodeCatalog, id)
	s.mu.Unlock()
	s.DisconnectNode(id)
}
func (s *ControllerServer) RefreshNode(ctx context.Context, id string) {
	_, _ = s.authorizedNode(ctx, id)
}

func (s *ControllerServer) RememberEnrolledNode(ctx context.Context, id string) {
	node, err := s.store.GetEdgeNode(ctx, id)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.forgottenNodes, id)
	if s.nodeCatalog == nil {
		s.nodeCatalog = map[string]db.EdgeNode{}
	}
	s.nodeCatalog[id] = *node
}
