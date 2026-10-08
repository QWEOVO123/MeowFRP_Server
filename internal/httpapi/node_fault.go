package httpapi

import (
	"context"
	"encoding/json"
	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/dpiengine"
	"frp-control-server/internal/security"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type faultClient struct {
	rowID                        int64
	tokenHash                    string
	tokenID                      int64
	clientID                     string
	draining, warned, logoutSent bool
	lastSeen                     time.Time
}
type nodeFaultState struct {
	mu                     sync.Mutex
	closed, databaseFailed bool
	clients                map[string]*faultClient
	drains                 map[string]bool
	localFailed            bool
}

func faultClientKey(hash, id string) string { return hash + ":" + strings.TrimSpace(id) }
func faultDrainKey(tokenID int64, id string) string {
	return strconv.FormatInt(tokenID, 10) + ":" + strings.TrimSpace(id)
}

func (s *Server) rememberClient(plain string, client *db.Client, login bool) {
	if client == nil {
		return
	}
	hash := security.TokenHash(plain)
	s.fault.mu.Lock()
	defer s.fault.mu.Unlock()
	key := faultClientKey(hash, client.ClientID)
	if c := s.fault.clients[key]; c != nil {
		if login && c.draining && !s.fault.closed && s.core.ClientProxyCount(c.tokenID, c.clientID) == 0 {
			s.core.FinishClientDrain(c.tokenID, c.clientID)
			delete(s.fault.drains, faultDrainKey(c.tokenID, c.clientID))
			c.draining = false
			c.warned = false
			c.logoutSent = false
		}
		c.lastSeen = time.Now()
		return
	}
	if login && !s.fault.closed && s.core.ClientProxyCount(client.TokenID, client.ClientID) == 0 {
		s.core.FinishClientDrain(client.TokenID, client.ClientID)
		delete(s.fault.drains, faultDrainKey(client.TokenID, client.ClientID))
	}
	s.fault.clients[key] = &faultClient{rowID: client.ID, tokenHash: hash, tokenID: client.TokenID, clientID: client.ClientID, lastSeen: time.Now()}
}
func (s *Server) nodeUnavailable() bool {
	if s.getConfig().Mode == config.ModeEdge {
		return !s.edgeOnlineForNewSessions()
	}
	s.fault.mu.Lock()
	defer s.fault.mu.Unlock()
	return s.fault.closed
}
func (s *Server) clientIsDraining(tokenID int64, clientID string) bool {
	s.fault.mu.Lock()
	defer s.fault.mu.Unlock()
	if s.fault.drains[faultDrainKey(tokenID, clientID)] {
		return true
	}
	return s.core.ClientDraining(tokenID, clientID)
}
func nodeFaultResponse(w http.ResponseWriter) {
	writeJSON(w, 503, map[string]any{"ok": false, "status": "node_fault", "error": "节点异常", "reason": "节点异常：暂不接受新登录或新穿透端口"})
}

func (s *Server) transitionNodeFault(closed bool) {
	if !closed && s.edgeState != nil {
		s.fault.mu.Lock()
		localFailed := s.fault.localFailed
		s.fault.mu.Unlock()
		if localFailed {
			return
		}
	}
	// Fence FRPS first, then mark authenticated GUI sessions for deferred logout.
	s.core.SetAdmissionClosed(closed)
	s.dpi.SetProviderUnavailable(closed, s.edgeState == nil)
	s.fault.mu.Lock()
	defer s.fault.mu.Unlock()
	changed := s.fault.closed != closed
	s.fault.closed = closed
	if closed {
		for _, c := range s.fault.clients {
			c.draining = true
			s.fault.drains[faultDrainKey(c.tokenID, c.clientID)] = true
		}
	}
	if changed {
		log.Printf("node admission changed: fault=%t; existing registered proxies are preserved", closed)
	}
}

func (s *Server) pauseDatabaseAdmission() {
	s.core.PauseAdmission()
	s.dpi.SetProviderUnavailable(true, true)
	s.fault.mu.Lock()
	s.fault.closed = true
	s.fault.mu.Unlock()
}

func (s *Server) runNodeHealth(ctx context.Context) {
	if s.getConfig().Mode == config.ModeEdge {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		var lastProbe time.Time
		for {
			if s.edgeState != nil && (lastProbe.IsZero() || time.Since(lastProbe) >= time.Second) {
				probeCtx, cancel := context.WithTimeout(ctx, time.Second)
				err := s.edgeState.CheckHealth(probeCtx)
				cancel()
				s.fault.mu.Lock()
				s.fault.localFailed = err != nil
				s.fault.mu.Unlock()
				if err != nil {
					log.Printf("edge local data database unavailable: %v", err)
				}
				lastProbe = time.Now()
			}
			closed := s.edgeClient == nil || s.edgeState == nil || !s.edgeClient.Connected() || s.edgeClient.ControllerFault() || s.edgeState.IdentityResetPending()
			s.fault.mu.Lock()
			old := s.fault.closed
			closed = closed || s.fault.localFailed
			s.fault.mu.Unlock()
			if old != closed {
				s.transitionNodeFault(closed)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
	var failedSince time.Time
	var lastCatalog time.Time
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		store := s.getStore()
		if store != nil {
			probeCtx, cancel := context.WithTimeout(ctx, time.Second)
			err := store.CheckHealth(probeCtx)
			cancel()
			s.observeControllerDatabaseHealth(time.Now(), err, &failedSince)
			if err == nil {
				if s.controllerControl != nil && (lastCatalog.IsZero() || time.Since(lastCatalog) > 5*time.Second) {
					catalogCtx, cancel := context.WithTimeout(ctx, time.Second)
					nodes, e := store.ListEdgeNodes(catalogCtx)
					cancel()
					if e == nil {
						s.controllerControl.ReplaceNodeCatalog(nodes)
						lastCatalog = time.Now()
					}
				}
			}
		}
		// Bound memory used by idle GUI sessions; active/draining tunnels retain
		// their credentials until closure. Never use this map for a fresh login.
		s.fault.mu.Lock()
		for key, c := range s.fault.clients {
			if time.Since(c.lastSeen) > 2*clientHeartbeatTimeout && s.core.ClientProxyCount(c.tokenID, c.clientID) == 0 {
				delete(s.fault.clients, key)
			}
		}
		s.fault.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Keep the transition independent of the polling clock so the 10-second
// boundary, brief outages and recovery can be tested deterministically.
func (s *Server) observeControllerDatabaseHealth(now time.Time, err error, failedSince *time.Time) {
	if err != nil {
		if failedSince.IsZero() {
			*failedSince = now
			log.Printf("controller database unavailable; starting 10s fault timer: %v", err)
			s.pauseDatabaseAdmission()
			if s.controllerControl != nil {
				s.controllerControl.SetDatabaseSuspect(true)
			}
		}
		if now.Sub(*failedSince) >= 10*time.Second {
			s.fault.mu.Lock()
			already := s.fault.databaseFailed
			s.fault.databaseFailed = true
			s.fault.mu.Unlock()
			if !already && s.controllerControl != nil {
				s.controllerControl.SetDatabaseFault(true)
			}
			if !already {
				log.Printf("controller database fault declared after 10s; draining local clients and refusing edge admission")
				s.transitionNodeFault(true)
			}
		}
		return
	}
	s.fault.mu.Lock()
	recovering := s.fault.closed
	s.fault.databaseFailed = false
	s.fault.mu.Unlock()
	if s.controllerControl != nil && s.controllerControl.DatabaseUnavailable() {
		recovering = true
	}
	if recovering {
		log.Printf("controller database recovered; resynchronizing edges before admission")
		if s.controllerControl != nil {
			s.controllerControl.SetDatabaseFault(false)
		}
		s.transitionNodeFault(false)
	}
	*failedSince = time.Time{}
}

// Heartbeats during faults must not depend on MySQL or discarded identity
// caches. Use only an already authenticated token fingerprint + device ID.
func (s *Server) faultHeartbeat(w http.ResponseWriter, r *http.Request, req clientHeartbeatRequest) bool {
	hash := security.TokenHash(req.AccessToken)
	s.fault.mu.Lock()
	c := s.fault.clients[faultClientKey(hash, req.ClientID)]
	closed := s.fault.closed
	databaseFailed := s.fault.databaseFailed
	if c == nil {
		s.fault.mu.Unlock()
		if s.nodeUnavailable() {
			nodeFaultResponse(w)
			return true
		}
		return false
	}
	if (closed && (s.edgeState != nil || databaseFailed)) || s.nodeUnavailableEdge() {
		c.draining = true
		s.fault.drains[faultDrainKey(c.tokenID, c.clientID)] = true
	}
	if !c.draining {
		if closed && s.edgeState == nil {
			c.lastSeen = time.Now()
			s.fault.mu.Unlock()
			writeJSON(w, 200, map[string]any{"ok": true, "status": "node_recovering", "reason": "数据库暂时不可用，正在等待恢复", "commands": []map[string]any{}, "heartbeat_interval": int(clientHeartbeatInterval.Seconds())})
			return true
		}
		s.fault.mu.Unlock()
		return false
	}
	c.lastSeen = time.Now()
	commands := []map[string]any{}
	count := s.core.ClientProxyCount(c.tokenID, c.clientID)
	rowID := c.rowID
	localHealthy := !s.fault.localFailed
	// An external, uninstrumented frps cannot prove there are zero proxies.
	authoritative := s.getConfig().EmbeddedFRPEnabled
	if count == 0 && authoritative {
		c.logoutSent = true
		commands = append(commands, map[string]any{"id": -2, "command": "reauth", "message": "节点异常：所有穿透端口已关闭，请重新登录"})
	} else if !c.warned {
		c.warned = true
		commands = append(commands, map[string]any{"id": -1, "command": "show_warning", "message": "节点异常：已开放的穿透端口继续运行，禁止新建端口；全部关闭后将自动登出"})
	}
	s.fault.mu.Unlock()
	// Presence is operational state, not an identity cache. Keep reporting
	// accurate after recovery without allowing a new login from this record.
	presenceCtx, cancel := context.WithTimeout(r.Context(), 250*time.Millisecond)
	if s.edgeState != nil && localHealthy {
		_ = s.edgeState.TouchClient(presenceCtx, rowID, count > 0 || req.FRPCRunning)
	} else if !closed && s.edgeState == nil && s.getStore() != nil {
		_ = s.getStore().TouchClientHeartbeat(presenceCtx, rowID, count > 0 || req.FRPCRunning)
	}
	cancel()
	writeJSON(w, 200, map[string]any{"ok": true, "status": "node_fault", "reason": "节点异常", "commands": commands, "active_proxies": count, "heartbeat_interval": int(clientHeartbeatInterval.Seconds())})
	return true
}
func (s *Server) nodeUnavailableEdge() bool {
	return s.getConfig().Mode == config.ModeEdge && (s.edgeClient == nil || !s.edgeClient.Connected() || s.edgeClient.ControllerFault() || s.edgeState.IdentityResetPending())
}

func (s *Server) rememberRuntime(r *http.Request, lease *db.RuntimeLease) {
	s.core.RememberRuntimeLease(*lease)
	s.dpi.PrimeLease(r.Context(), dpiengine.FlowContext{UserID: lease.UserID, TokenID: lease.TokenID, LeaseID: lease.LeaseID, ClientID: lease.ClientID})
}

func (s *Server) allowFaultRuntime(metas map[string]string) bool {
	lease, ok := s.core.ExistingRuntime(metas["lease_id"], security.TokenHash(metas["token"]))
	s.fault.mu.Lock()
	closed := s.fault.closed
	s.fault.mu.Unlock()
	return ok && (closed || s.nodeUnavailableEdge() || s.clientIsDraining(lease.TokenID, lease.ClientID))
}

func (s *Server) guardNodeAdmission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/api/v1/client/login" || path == "/api/v1/client/resource-policy" || path == "/api/v1/client/bootstrap" {
			if s.nodeUnavailable() {
				nodeFaultResponse(w)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) faultFRPPlugin(w http.ResponseWriter, req frpPluginRequest) bool {
	if req.Op == "Login" || req.Op == "NewProxy" {
		if s.nodeUnavailable() {
			writeJSON(w, 200, frpReject("节点异常：禁止新登录和新穿透端口"))
			return true
		}
		return false
	}
	if req.Op != "Ping" && req.Op != "NewWorkConn" && req.Op != "NewUserConn" {
		return false
	}
	var content struct {
		User frpUserInfo `json:"user"`
	}
	if json.Unmarshal(req.Content, &content) != nil {
		return false
	}
	if s.allowFaultRuntime(content.User.Metas) {
		writeJSON(w, 200, frpAllow())
		return true
	}
	return false
}

func (s *Server) databaseRejection(err error) map[string]any {
	log.Printf("client database operation failed; preserving existing runtime: %v", err)
	s.pauseDatabaseAdmission()
	if s.controllerControl != nil {
		s.controllerControl.SetDatabaseSuspect(true)
	}
	return map[string]any{"ok": false, "status": "database_unavailable", "reason": "节点异常：数据库暂时不可用"}
}
