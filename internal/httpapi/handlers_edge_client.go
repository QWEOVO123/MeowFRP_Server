package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"frp-control-server/internal/db"
	"frp-control-server/internal/edgestate"
	"frp-control-server/internal/security"
)

func (s *Server) edgeOnlineForNewSessions() bool {
	return s.edgeState != nil && s.edgeClient != nil && s.edgeClient.Connected() && s.edgeClient.SyncReady()
}
func edgeDisconnected(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "status": "edge_controller_disconnected", "error": "edge_controller_disconnected", "reason": "边缘节点与中心节点失联"})
}

func (s *Server) edgeCredential(r *http.Request, plain, clientID string, create bool) (*db.AccessToken, *db.User, *db.Client, map[string]any) {
	if s.edgeState == nil {
		return nil, nil, nil, map[string]any{"ok": false, "status": "error", "reason": "edge state is unavailable"}
	}
	t, u, c, err := s.edgeState.Credential(r.Context(), security.TokenHash(plain), strings.TrimSpace(clientID), create)
	if err != nil {
		return nil, nil, nil, map[string]any{"ok": false, "status": "unauthorized", "reason": "invalid access token"}
	}
	if err := edgestate.ValidateCredential(t, u, c); err != nil {
		return nil, nil, nil, map[string]any{"ok": false, "status": "rejected", "reason": err.Error()}
	}
	return t, u, c, nil
}

func (s *Server) edgeClientResourcePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.edgeOnlineForNewSessions() {
		edgeDisconnected(w)
		return
	}
	var req clientResourcePolicyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	t, u, c, reject := s.edgeCredential(r, req.AccessToken, req.ClientID, true)
	if reject != nil {
		writeJSON(w, 200, reject)
		return
	}
	p, err := s.edgeState.Policy(r.Context(), u.ID)
	if err != nil || !p.Enabled {
		writeJSON(w, 200, map[string]any{"ok": false, "status": "rejected", "reason": "resource policy is not configured"})
		return
	}
	_ = s.edgeState.TouchClientSeen(r.Context(), c.ID)
	cfg := s.getConfig()
	p, rangeAvailable := intersectNodePortRange(p, cfg)
	if !rangeAvailable {
		writeJSON(w, 200, map[string]any{"ok": false, "status": "rejected", "reason": "node and user port ranges do not overlap"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "user": u.Username, "token": t.Name, "policy": p, "dpi": clientDPISummary{Enabled: false, Mode: "monitor", EnabledDetectors: []string{}, BlockedTrafficTypes: []string{}, AllowedTrafficTypes: []string{}}, "frp_server_addr": cfg.FRPServerAddr, "frp_server_port": cfg.FRPServerPort, "frp_transport_tls": cfg.FRPTransportTLS})
}

func (s *Server) edgeClientBootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.edgeOnlineForNewSessions() {
		edgeDisconnected(w)
		return
	}
	var req clientBootstrapRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	t, u, c, reject := s.edgeCredential(r, req.AccessToken, req.ClientID, false)
	if reject != nil {
		writeJSON(w, 200, reject)
		return
	}
	if !s.edgeState.ClientFresh(r.Context(), c.ID, int(clientHeartbeatTimeout.Seconds())) {
		writeJSON(w, 200, map[string]any{"ok": false, "status": "heartbeat_timeout", "reason": "client heartbeat timeout, please reconnect"})
		return
	}
	allocations, err := s.validateEdgeProxies(r, t, u, req.Proxies)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "status": "rejected", "reason": err.Error()})
		return
	}
	runtimeToken, runtimeHash, err := security.NewOpaqueToken("rt_")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	leaseID, _, err := security.NewOpaqueToken("lease_")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	expires := time.Now().Add(s.getConfig().RuntimeTokenTTL)
	lease := db.RuntimeLease{LeaseID: leaseID, UserID: u.ID, TokenID: t.ID, ClientID: req.ClientID, RuntimeTokenHash: runtimeHash, Status: "active", ExpiresAt: expires}
	if err := s.edgeState.CreateLease(r.Context(), lease, allocations); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "lease_id": leaseID, "expires_at": expires, "expires_in": int(s.getConfig().RuntimeTokenTTL.Seconds()), "frpc_config": s.renderFrpcConfig(u, leaseID, runtimeToken, allocations), "allocations": allocations})
}

func (s *Server) validateEdgeProxies(r *http.Request, t *db.AccessToken, u *db.User, input []db.ProxyAllocationInput) ([]db.ProxyAllocationInput, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("at least one proxy is required")
	}
	p, err := s.edgeState.Policy(r.Context(), u.ID)
	if err != nil || !p.Enabled {
		return nil, fmt.Errorf("resource policy is not configured")
	}
	if p.MaxPorts > 0 && len(input) > p.MaxPorts {
		return nil, fmt.Errorf("proxy count exceeds user limit")
	}
	if t.MaxProxyCount > 0 && len(input) > t.MaxProxyCount {
		return nil, fmt.Errorf("proxy count exceeds token limit")
	}
	cfg := s.getConfig()
	p, rangeAvailable := intersectNodePortRange(p, cfg)
	if !rangeAvailable {
		return nil, fmt.Errorf("node and user port ranges do not overlap")
	}
	grants, _ := s.edgeState.Grants(r.Context(), t.ID)
	requestedPorts := map[string]bool{}
	for i := range input {
		v := &input[i]
		v.ProxyName = strings.TrimSpace(v.ProxyName)
		v.ProxyType = normalizeProtocol(v.ProxyType)
		v.LocalIP = strings.TrimSpace(v.LocalIP)
		if v.LocalIP == "" {
			v.LocalIP = "127.0.0.1"
		}
		if v.ProxyName == "" || v.LocalPort <= 0 || (v.ProxyType != "tcp" && v.ProxyType != "udp") {
			return nil, fmt.Errorf("invalid proxy")
		}
		if !protocolAllowed(v.ProxyType, p.AllowedProtocols) || v.RemotePort < p.PortStart || v.RemotePort > p.PortEnd {
			return nil, fmt.Errorf("proxy %s is outside policy", v.ProxyName)
		}
		if err := validateNodeRemotePort(cfg, v.RemotePort); err != nil {
			return nil, err
		}
		portKey := fmt.Sprintf("%s:%d", v.ProxyType, v.RemotePort)
		if requestedPorts[portKey] {
			return nil, fmt.Errorf("remote port %d is duplicated in this request", v.RemotePort)
		}
		requestedPorts[portKey] = true
		if used, err := s.edgeState.RemotePortInUse(r.Context(), v.ProxyType, v.RemotePort); err != nil {
			return nil, err
		} else if used {
			return nil, fmt.Errorf("remote port %d is already in use on this node", v.RemotePort)
		}
		if len(grants) > 0 && !matchesAnyGrant(*v, grants) {
			return nil, fmt.Errorf("proxy %s is not covered by token grants", v.ProxyName)
		}
	}
	return input, nil
}

func (s *Server) edgeClientHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req clientHeartbeatRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_, _, c, reject := s.edgeCredential(r, req.AccessToken, req.ClientID, true)
	if reject != nil {
		writeJSON(w, 200, reject)
		return
	}
	_ = s.edgeState.TouchClient(r.Context(), c.ID, req.FRPCRunning)
	commands := []map[string]any{}
	if queued, err := s.edgeState.PopClientCommands(r.Context(), c.ID); err == nil {
		commands = append(commands, queued...)
	}
	if !s.edgeOnlineForNewSessions() {
		if !req.FRPCRunning {
			edgeDisconnected(w)
			return
		}
		if show, _ := s.edgeState.DisconnectWarning(r.Context(), c.ID); show {
			commands = append(commands, map[string]any{"id": -1, "command": "show_warning", "message": "边缘节点与中心节点失联；已建立的 FRP 将继续运行，但暂时不能新建连接。"})
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": "ok", "commands": commands, "heartbeat_interval": int(clientHeartbeatInterval.Seconds())})
}

func (s *Server) edgeClientCommandACK(w http.ResponseWriter, r *http.Request) {
	commandID, err := parseID(r)
	if err != nil || commandID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid command id")
		return
	}
	var req clientHeartbeatRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _, client, reject := s.edgeCredential(r, req.AccessToken, req.ClientID, false)
	if reject != nil {
		writeJSON(w, http.StatusOK, reject)
		return
	}
	if err := s.edgeState.AcknowledgeClientCommand(r.Context(), commandID, client.ID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "command not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "acknowledged", "command_id": commandID})
}

func (s *Server) edgeClientLogout(w http.ResponseWriter, r *http.Request) {
	var req clientHeartbeatRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	t, _, c, reject := s.edgeCredential(r, req.AccessToken, req.ClientID, false)
	if reject != nil {
		writeJSON(w, 200, reject)
		return
	}
	_ = s.edgeState.RevokeClient(r.Context(), t.ID, req.ClientID)
	deletedCommands, _ := s.edgeState.DeleteUnacknowledgedClientCommands(r.Context(), c.ID)
	_ = s.edgeState.ClearClient(r.Context(), c.ID)
	terminated := 0
	if s.core != nil {
		terminated = s.core.TerminateConnectionsForClient(t.ID, req.ClientID)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": "logged_out", "terminated": terminated, "deleted_commands": deletedCommands})
}

func (s *Server) edgeFrpPlugin(w http.ResponseWriter, r *http.Request) {
	if s.edgeState == nil {
		writeJSON(w, 200, frpReject("edge state unavailable"))
		return
	}
	var req frpPluginRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, 200, frpReject("bad plugin request"))
		return
	}
	switch req.Op {
	case "Login":
		var c frpLoginContent
		if json.Unmarshal(req.Content, &c) != nil {
			writeJSON(w, 200, frpReject("bad Login content"))
			return
		}
		_, reason := s.edgeRuntime(r, c.Metas)
		if reason != "" {
			writeJSON(w, 200, frpReject(reason))
			return
		}
		writeJSON(w, 200, frpAllow())
	case "NewProxy":
		var c frpNewProxyContent
		if json.Unmarshal(req.Content, &c) != nil {
			writeJSON(w, 200, frpReject("bad NewProxy content"))
			return
		}
		l, reason := s.edgeRuntime(r, c.User.Metas)
		if reason != "" {
			writeJSON(w, 200, frpReject(reason))
			return
		}
		name := stripFRPUserProxyPrefix(l.UserID, c.ProxyName)
		if !s.edgeState.AllocationExists(r.Context(), l.LeaseID, name, normalizeProtocol(c.ProxyType), c.RemotePort, first(c.CustomDomains), strings.TrimSpace(c.Subdomain)) {
			writeJSON(w, 200, frpReject("proxy is not allocated by current lease"))
			return
		}
		writeJSON(w, 200, frpAllow())
	case "Ping", "NewWorkConn", "NewUserConn":
		var metas map[string]string
		if req.Op == "Ping" {
			var c frpPingContent
			_ = json.Unmarshal(req.Content, &c)
			metas = c.User.Metas
		} else if req.Op == "NewWorkConn" {
			var c frpNewWorkConnContent
			_ = json.Unmarshal(req.Content, &c)
			metas = c.User.Metas
		} else {
			var c frpNewUserConnContent
			_ = json.Unmarshal(req.Content, &c)
			metas = c.User.Metas
		}
		_, reason := s.edgeRuntime(r, metas)
		if reason != "" {
			writeJSON(w, 200, frpReject(reason))
			return
		}
		writeJSON(w, 200, frpAllow())
	default:
		writeJSON(w, 200, frpAllow())
	}
}
func (s *Server) edgeRuntime(r *http.Request, metas map[string]string) (*db.RuntimeLease, string) {
	token, leaseID := metas["token"], metas["lease_id"]
	if token == "" || leaseID == "" {
		return nil, "missing runtime token or lease_id"
	}
	l, err := s.edgeState.RuntimeLease(r.Context(), security.TokenHash(token))
	if err != nil || l.LeaseID != leaseID {
		return nil, "invalid runtime token"
	}
	if l.Status != "active" || time.Now().After(l.ExpiresAt) {
		return nil, "runtime lease expired or inactive"
	}
	if err := s.edgeState.RuntimeAuthorized(r.Context(), l.UserID, l.TokenID); err != nil {
		return nil, err.Error()
	}
	// Runtime validation intentionally does not require the Controller connection.
	if !s.edgeState.RuntimeClientFresh(r.Context(), l.TokenID, l.ClientID, int(clientHeartbeatTimeout.Seconds())) {
		return nil, "client heartbeat timeout"
	}
	return l, ""
}
