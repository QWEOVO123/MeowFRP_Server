package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"frp-control-server/internal/db"
	"frp-control-server/internal/edgestate"
	"frp-control-server/internal/frpcore"
	"frp-control-server/internal/security"
)

func (s *Server) edgeOnlineForNewSessions() bool {
	s.fault.mu.Lock()
	failed := s.fault.closed || s.fault.localFailed
	s.fault.mu.Unlock()
	return !failed && s.edgeState != nil && s.edgeClient != nil && s.edgeClient.Connected() && s.edgeClient.SyncReady() && !s.edgeClient.ControllerFault()
}
func edgeDisconnected(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "status": "edge_controller_disconnected", "error": "edge_controller_disconnected", "reason": "边缘控制通道不可用或用户信息正在同步，请稍后重试"})
}

func (s *Server) edgeCredential(r *http.Request, plain, clientID string, create bool) (*db.AccessToken, *db.User, *db.Client, map[string]any) {
	if s.edgeState == nil {
		return nil, nil, nil, map[string]any{"ok": false, "status": "error", "reason": "edge state is unavailable"}
	}
	t, u, c, err := s.edgeState.Credential(r.Context(), security.TokenHash(plain), strings.TrimSpace(clientID), create)
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) && !errors.Is(err, sql.ErrNoRows) {
			s.transitionNodeFault(true)
			return nil, nil, nil, map[string]any{"ok": false, "status": "database_unavailable", "reason": "节点异常：本地 data 数据库暂时不可用"}
		}
		return nil, nil, nil, map[string]any{"ok": false, "status": "unauthorized", "reason": "invalid access token"}
	}
	if err := edgestate.ValidateCredential(t, u, c); err != nil {
		return nil, nil, nil, map[string]any{"ok": false, "status": "rejected", "reason": err.Error()}
	}
	if s.clientIsDraining(c.TokenID, c.ClientID) && strings.HasSuffix(r.URL.Path, "/bootstrap") {
		return nil, nil, nil, map[string]any{"ok": false, "status": "node_fault", "reason": "节点异常：请关闭全部穿透端口后重新登录"}
	}
	s.rememberClient(plain, c, strings.HasSuffix(r.URL.Path, "/resource-policy"))
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
		writeJSON(w, 200, map[string]any{"ok": false, "status": "rejected", "reason": "资源策略未同步或已禁用，请检查中心用户资源策略；刚保存后请稍候重新选择节点"})
		return
	}
	_ = s.edgeState.TouchClientSeen(r.Context(), c.ID)
	cfg := s.getConfig()
	p, rangeAvailable := intersectNodePortRange(p, cfg)
	if !rangeAvailable {
		writeJSON(w, 200, map[string]any{"ok": false, "status": "rejected", "reason": "node and user port ranges do not overlap"})
		return
	}
	dpiPolicy, err := s.edgeState.DPIPolicy(r.Context(), u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read cached DPI policy failed")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "user": u.Username, "token": t.Name, "policy": p, "dpi": clientDPISummaryFromPolicy(dpiPolicy), "frp_server_addr": cfg.FRPServerAddr, "frp_server_port": cfg.FRPServerPort, "frp_transport_tls": cfg.FRPTransportTLS})
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
	allocations, err := s.validateEdgeProxies(r, t, u, req.Proxies, req.ClientID)
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

func (s *Server) validateEdgeProxies(r *http.Request, t *db.AccessToken, u *db.User, input []db.ProxyAllocationInput, clientIDs ...string) ([]db.ProxyAllocationInput, error) {
	clientID := ""
	if len(clientIDs) > 0 {
		clientID = clientIDs[0]
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("at least one proxy is required")
	}
	p, err := s.edgeState.Policy(r.Context(), u.ID)
	if err != nil || !p.Enabled {
		return nil, fmt.Errorf("资源策略未同步或已禁用，请检查中心用户资源策略；刚保存后请稍候重新选择节点")
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
	grants, err := s.edgeState.Grants(r.Context(), t.ID)
	if err != nil {
		return nil, fmt.Errorf("read token grants: %w", err)
	}
	requestedPorts := map[string]bool{}
	requestedNames := map[string]bool{}
	for i := range input {
		v := &input[i]
		v.ProxyName = strings.TrimSpace(v.ProxyName)
		v.ProxyType = normalizeProtocol(v.ProxyType)
		v.LocalIP = strings.TrimSpace(v.LocalIP)
		v.Domain = strings.TrimSpace(v.Domain)
		v.Subdomain = strings.TrimSpace(v.Subdomain)
		if v.LocalIP == "" {
			v.LocalIP = "127.0.0.1"
		}
		if v.ProxyName == "" || v.LocalPort <= 0 || v.LocalPort > 65535 || (v.ProxyType != "tcp" && v.ProxyType != "udp") {
			return nil, fmt.Errorf("invalid proxy")
		}
		if requestedNames[v.ProxyName] {
			return nil, fmt.Errorf("proxy name %s is duplicated", v.ProxyName)
		}
		requestedNames[v.ProxyName] = true
		if len(v.ProxyName) > 48 {
			return nil, fmt.Errorf("proxy name must not exceed 48 bytes")
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
		if used, err := s.edgeState.RemotePortInUseExceptClient(r.Context(), v.ProxyType, v.RemotePort, t.ID, clientID); err != nil {
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
	if s.faultHeartbeat(w, r, req) {
		return
	}
	if !s.edgeOnlineForNewSessions() {
		nodeFaultResponse(w)
		return
	}
	_, _, c, reject := s.edgeCredential(r, req.AccessToken, req.ClientID, true)
	if reject != nil {
		if s.edgeState.IdentityResetPending() {
			edgeDisconnected(w)
			return
		}
		writeJSON(w, 200, reject)
		return
	}
	if err := s.edgeState.TouchClient(r.Context(), c.ID, req.FRPCRunning); err != nil {
		writeError(w, 500, "save client heartbeat failed")
		return
	}
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
			commands = append(commands, map[string]any{"id": -1, "command": "show_warning", "message": "边缘节点与中心节点失联或正在同步；暂时无法新建连接，部分业务连接可能需要等待同步后重连。"})
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
	if err := s.edgeState.RevokeClient(r.Context(), t.ID, req.ClientID); err != nil {
		writeError(w, 500, "revoke client runtime failed")
		return
	}
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
	if s.faultFRPPlugin(w, req) {
		return
	}
	switch req.Op {
	case "Login":
		var c frpLoginContent
		if json.Unmarshal(req.Content, &c) != nil {
			writeJSON(w, 200, frpReject("bad Login content"))
			return
		}
		lease, reason := s.edgeRuntime(r, c.Metas)
		if reason != "" {
			writeJSON(w, 200, frpReject(reason))
			return
		}
		s.rememberRuntime(r, lease)
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
		name := stripFRPUserProxyPrefix(l.UserID, c.ProxyName, l.LeaseID)
		if s.clientIsDraining(l.TokenID, l.ClientID) {
			writeJSON(w, 200, frpReject("节点异常：禁止开启新穿透端口"))
			return
		}
		if !s.edgeState.AllocationExists(r.Context(), l.LeaseID, name, normalizeProtocol(c.ProxyType), c.RemotePort, first(c.CustomDomains), strings.TrimSpace(c.Subdomain)) {
			writeJSON(w, 200, frpReject("proxy is not allocated by current lease"))
			return
		}
		s.core.BindProxy(frpcore.ProxyBinding{UserID: l.UserID, TokenID: l.TokenID, ClientID: l.ClientID, LeaseID: l.LeaseID, ProxyName: c.ProxyName, ProxyType: c.ProxyType, RemotePort: c.RemotePort})
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
