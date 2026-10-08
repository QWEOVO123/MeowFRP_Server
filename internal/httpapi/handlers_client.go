package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	dpipolicy "frp-control-server/internal/dpi"
	"frp-control-server/internal/policy"
	"frp-control-server/internal/security"
)

type clientBootstrapRequest struct {
	AccessToken   string                    `json:"access_token"`
	ClientID      string                    `json:"client_id"`
	ClientVersion string                    `json:"client_version"`
	Proxies       []db.ProxyAllocationInput `json:"proxies"`
}

type clientResourcePolicyRequest struct {
	AccessToken string `json:"access_token"`
	ClientID    string `json:"client_id"`
}

type clientDPISummary struct {
	Enabled             bool     `json:"enabled"`
	Mode                string   `json:"mode"`
	EnabledDetectors    []string `json:"enabled_detectors"`
	BlockedTrafficTypes []string `json:"blocked_traffic_types"`
	AllowedTrafficTypes []string `json:"allowed_traffic_types"`
	BlockOnAnyFinding   bool     `json:"block_on_any_finding"`
}

func (s *Server) clientResourcePolicy(w http.ResponseWriter, r *http.Request) {
	if s.getConfig().Mode == config.ModeEdge {
		s.edgeClientResourcePolicy(w, r)
		return
	}
	store := s.getStore()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "system setup required")
		return
	}
	var req clientResourcePolicyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	token, user, client, reject := s.validateAccessTokenRequest(r, store, req.AccessToken, req.ClientID)
	if reject != nil {
		writeJSON(w, http.StatusOK, reject)
		return
	}
	policy, err := store.GetUserResourcePolicy(r.Context(), user.ID)
	if err != nil || !policy.Enabled {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     false,
			"status": "rejected",
			"reason": "资源策略尚未配置或已禁用，请在中心用户详情中检查资源策略并保存",
		})
		return
	}
	if err := store.TouchClientHeartbeat(r.Context(), client.ID, client.FRPCRunning); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg := s.getConfig()
	policy, rangeAvailable := intersectNodePortRange(policy, cfg)
	if !rangeAvailable {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "status": "rejected", "reason": "node and user port ranges do not overlap"})
		return
	}
	dpiSummary := clientDPIStatus(r.Context(), store, user.ID)
	store.Audit(r.Context(), "client", client.ID, "resource_policy", "token", fmt.Sprintf("%d", token.ID), "")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"user":              user.Username,
		"token":             token.Name,
		"policy":            policy,
		"dpi":               dpiSummary,
		"frp_server_addr":   cfg.FRPServerAddr,
		"frp_server_port":   cfg.FRPServerPort,
		"frp_transport_tls": cfg.FRPTransportTLS,
		"message":           "choose a remote port inside this range, then request bootstrap",
	})
}

func clientDPIStatus(ctx context.Context, store *db.Store, userID int64) clientDPISummary {
	policy, err := store.GetDPIPolicy(ctx, userID)
	if err != nil {
		policy = dpipolicy.DefaultPolicy()
	}
	return clientDPISummaryFromPolicy(policy)
}

func clientDPISummaryFromPolicy(policy dpipolicy.Policy) clientDPISummary {
	enabledDetectors := normalizeDPIDetectors(policy.EnabledDetectors)
	if len(enabledDetectors) == 0 {
		enabledDetectors = normalizeDPIDetectors(dpipolicy.DefaultPolicy().EnabledDetectors)
	}
	summary := clientDPISummary{
		Enabled:             policy.Enabled,
		Mode:                string(policy.Mode),
		EnabledDetectors:    enabledDetectors,
		BlockedTrafficTypes: []string{},
		AllowedTrafficTypes: []string{},
		BlockOnAnyFinding:   policy.BlockOnAnyFinding,
	}
	if summary.Mode == "" {
		summary.Mode = string(dpipolicy.ModeMonitor)
	}
	if !policy.Enabled {
		return summary
	}
	for _, trafficType := range []string{"http", "tls", "quic", "encrypted_tunnel"} {
		if detectorEnabled(trafficType, enabledDetectors) && dpiTypeAllowed(policy, trafficType) {
			summary.AllowedTrafficTypes = append(summary.AllowedTrafficTypes, trafficType)
		}
	}
	if policy.Mode != dpipolicy.ModeBlock {
		return summary
	}
	if policy.BlockOnAnyFinding {
		summary.BlockedTrafficTypes = append(summary.BlockedTrafficTypes, enabledDetectors...)
		return summary
	}
	for _, trafficType := range []string{"http", "tls", "quic", "encrypted_tunnel"} {
		if detectorEnabled(trafficType, enabledDetectors) && !dpiTypeAllowed(policy, trafficType) {
			summary.BlockedTrafficTypes = append(summary.BlockedTrafficTypes, trafficType)
		}
	}
	return summary
}

func detectorEnabled(trafficType string, enabledDetectors []string) bool {
	for _, detector := range enabledDetectors {
		if detector == trafficType {
			return true
		}
	}
	return false
}

func dpiTypeAllowed(policy dpipolicy.Policy, trafficType string) bool {
	switch trafficType {
	case "http":
		return policy.AllowHTTP
	case "tls":
		return policy.AllowTLS
	case "quic":
		return policy.AllowQUIC
	case "encrypted_tunnel":
		return policy.AllowEncryptedTunnel
	default:
		return true
	}
}

func (s *Server) clientBootstrap(w http.ResponseWriter, r *http.Request) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	if s.getConfig().Mode == config.ModeEdge {
		s.edgeClientBootstrap(w, r)
		return
	}
	store := s.getStore()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "system setup required")
		return
	}
	var req clientBootstrapRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.AccessToken == "" || req.ClientID == "" {
		writeError(w, http.StatusBadRequest, "access_token and client_id are required")
		return
	}

	token, user, client, reject := s.validateExistingAccessTokenRequest(r, store, req.AccessToken, req.ClientID)
	if reject != nil {
		writeJSON(w, http.StatusOK, reject)
		return
	}
	fresh, err := store.IsClientHeartbeatFresh(r.Context(), client.ID, int(clientHeartbeatTimeout.Seconds()))
	if err != nil || !fresh {
		terminated := s.terminateClientRuntime(r.Context(), *client, "client heartbeat timeout")
		store.Audit(r.Context(), "system", 0, "client_heartbeat_timeout", "client", fmt.Sprintf("%d", client.ID), fmt.Sprintf("bootstrap rejected, terminated %d", terminated))
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "status": "heartbeat_timeout", "reason": "client heartbeat timeout, please reconnect"})
		return
	}

	if decision := s.policy.BeforeClientBootstrap(r.Context(), policy.BootstrapInput{
		UserID: user.ID, TokenID: token.ID, ClientID: req.ClientID,
	}); decision.Action != policy.ActionAllow {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "status": decision.Action, "reason": decision.Reason})
		return
	}

	allocations, err := s.validateBootstrapProxies(r.Context(), user, token, req.Proxies, req.ClientID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "status": "rejected", "reason": err.Error()})
		return
	}

	runtimeToken, runtimeHash, err := security.NewOpaqueToken("rt_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	leaseID, _, err := security.NewOpaqueToken("lease_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg := s.getConfig()
	expiresAt := time.Now().Add(cfg.RuntimeTokenTTL)
	if err := store.CreateRuntimeLease(r.Context(), leaseID, user.ID, token.ID, req.ClientID, runtimeHash, security.TokenPrefix(runtimeToken), expiresAt, allocations); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	frpcConfig := s.renderFrpcConfig(user, leaseID, runtimeToken, allocations)
	store.Audit(r.Context(), "client", client.ID, "bootstrap", "lease", leaseID, fmt.Sprintf("allocated %d proxies", len(allocations)))

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"lease_id":     leaseID,
		"expires_at":   expiresAt,
		"expires_in":   int(cfg.RuntimeTokenTTL.Seconds()),
		"frpc_config":  frpcConfig,
		"allocations":  allocations,
		"frp_server":   cfg.FRPServerAddr,
		"frp_port":     cfg.FRPServerPort,
		"token_prefix": security.TokenPrefix(runtimeToken),
	})
}

func (s *Server) validateBootstrapProxies(ctx context.Context, user *db.User, token *db.AccessToken, proxies []db.ProxyAllocationInput, clientIDs ...string) ([]db.ProxyAllocationInput, error) {
	clientID := ""
	if len(clientIDs) > 0 {
		clientID = clientIDs[0]
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("at least one proxy is required")
	}
	policy, err := s.store.GetUserResourcePolicy(ctx, user.ID)
	if err != nil || !policy.Enabled {
		return nil, fmt.Errorf("资源策略尚未配置或已禁用，请在中心用户详情中检查资源策略并保存")
	}
	if policy.MaxPorts > 0 && len(proxies) > policy.MaxPorts {
		return nil, fmt.Errorf("proxy count %d exceeds user limit %d", len(proxies), policy.MaxPorts)
	}
	if token.MaxProxyCount > 0 && len(proxies) > token.MaxProxyCount {
		return nil, fmt.Errorf("proxy count %d exceeds token limit %d", len(proxies), token.MaxProxyCount)
	}
	cfg := s.getConfig()
	policy, rangeAvailable := intersectNodePortRange(policy, cfg)
	if !rangeAvailable {
		return nil, fmt.Errorf("node and user port ranges do not overlap")
	}
	grants, err := s.store.ListPortGrants(ctx, token.ID)
	if err != nil {
		return nil, fmt.Errorf("read token grants: %w", err)
	}
	var normalized []db.ProxyAllocationInput
	requestedPorts := map[string]bool{}
	requestedNames := map[string]bool{}
	for _, proxy := range proxies {
		proxy.ProxyName = strings.TrimSpace(proxy.ProxyName)
		proxy.ProxyType = normalizeProtocol(proxy.ProxyType)
		proxy.LocalIP = strings.TrimSpace(proxy.LocalIP)
		proxy.Domain = strings.TrimSpace(proxy.Domain)
		proxy.Subdomain = strings.TrimSpace(proxy.Subdomain)
		if proxy.ProxyName == "" || proxy.ProxyType == "" || proxy.LocalPort <= 0 || proxy.LocalPort > 65535 {
			return nil, fmt.Errorf("proxy name, supported type and local_port are required")
		}
		if requestedNames[proxy.ProxyName] {
			return nil, fmt.Errorf("proxy name %s is duplicated", proxy.ProxyName)
		}
		requestedNames[proxy.ProxyName] = true
		if len(proxy.ProxyName) > 48 {
			return nil, fmt.Errorf("proxy name must not exceed 48 bytes")
		}
		if proxy.LocalIP == "" {
			proxy.LocalIP = "127.0.0.1"
		}
		if !protocolAllowed(proxy.ProxyType, policy.AllowedProtocols) {
			return nil, fmt.Errorf("protocol %s is not enabled for this user", proxy.ProxyType)
		}
		if proxy.ProxyType != "tcp" && proxy.ProxyType != "udp" {
			return nil, fmt.Errorf("user-selected server ports currently support tcp/udp only")
		}
		if proxy.RemotePort < policy.PortStart || proxy.RemotePort > policy.PortEnd {
			return nil, fmt.Errorf("remote port %d is outside user range %d-%d", proxy.RemotePort, policy.PortStart, policy.PortEnd)
		}
		if err := validateNodeRemotePort(cfg, proxy.RemotePort); err != nil {
			return nil, err
		}
		portKey := fmt.Sprintf("%s:%d", proxy.ProxyType, proxy.RemotePort)
		if requestedPorts[portKey] {
			return nil, fmt.Errorf("remote port %d is duplicated in this request", proxy.RemotePort)
		}
		requestedPorts[portKey] = true
		if used, err := s.store.RemotePortInUseExceptClient(ctx, proxy.ProxyType, proxy.RemotePort, token.ID, clientID); err != nil {
			return nil, err
		} else if used {
			return nil, fmt.Errorf("remote port %d is already in use on this node", proxy.RemotePort)
		}
		if !matchesAnyGrant(proxy, grants) {
			if len(grants) > 0 {
				return nil, fmt.Errorf("proxy %s is not covered by token grants", proxy.ProxyName)
			}
		}
		normalized = append(normalized, proxy)
	}
	return normalized, nil
}

func (s *Server) validateAccessTokenRequest(r *http.Request, store *db.Store, accessToken, clientID string) (*db.AccessToken, *db.User, *db.Client, map[string]any) {
	return s.validateAccessTokenRequestWithClientMode(r, store, accessToken, clientID, true)
}

func (s *Server) validateExistingAccessTokenRequest(r *http.Request, store *db.Store, accessToken, clientID string) (*db.AccessToken, *db.User, *db.Client, map[string]any) {
	return s.validateAccessTokenRequestWithClientMode(r, store, accessToken, clientID, false)
}

func (s *Server) validateAccessTokenRequestWithClientMode(r *http.Request, store *db.Store, accessToken, clientID string, createClient bool) (*db.AccessToken, *db.User, *db.Client, map[string]any) {
	token, err := store.GetAccessTokenByHash(r.Context(), security.TokenHash(accessToken))
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return nil, nil, nil, s.databaseRejection(err)
		}
		return nil, nil, nil, map[string]any{"ok": false, "status": "unauthorized", "reason": "invalid access token"}
	}
	user, err := store.GetUserByID(r.Context(), token.UserID)
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return nil, nil, nil, s.databaseRejection(err)
		}
		return nil, nil, nil, map[string]any{"ok": false, "status": "unauthorized", "reason": "invalid token owner"}
	}
	if user.Role != "user" {
		return nil, nil, nil, map[string]any{"ok": false, "status": "unauthorized", "reason": "admin accounts cannot use frp access"}
	}
	allowed, accessErr := store.CanAccessNode(r.Context(), user.ID, "controller")
	if accessErr != nil {
		return nil, nil, nil, s.databaseRejection(accessErr)
	}
	if !allowed {
		return nil, nil, nil, map[string]any{"ok": false, "status": "forbidden", "reason": "该账号没有此节点的使用权限"}
	}
	if user.Status == "banned" {
		return nil, nil, nil, map[string]any{"ok": false, "status": "banned", "reason": user.BanReason}
	}
	if user.Status != "active" {
		return nil, nil, nil, map[string]any{"ok": false, "status": user.Status, "reason": "user is not active"}
	}
	if token.Status == "banned" {
		return nil, nil, nil, map[string]any{"ok": false, "status": "banned", "reason": token.BanReason}
	}
	if token.Status != "active" {
		return nil, nil, nil, map[string]any{"ok": false, "status": token.Status, "reason": "token is not active"}
	}
	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
		return nil, nil, nil, map[string]any{"ok": false, "status": "expired", "reason": "token expired"}
	}
	var client *db.Client
	if createClient {
		client, err = store.FindOrCreateClient(r.Context(), user.ID, token.ID, clientID)
		if err != nil {
			return nil, nil, nil, s.databaseRejection(err)
		}
	} else {
		client, err = store.GetClient(r.Context(), token.ID, clientID)
		if err != nil {
			if !errors.Is(err, db.ErrNotFound) {
				return nil, nil, nil, s.databaseRejection(err)
			}
			return nil, nil, nil, map[string]any{"ok": false, "status": "heartbeat_required", "reason": "client heartbeat is required before bootstrap"}
		}
	}
	if client.Status == "banned" {
		return nil, nil, nil, map[string]any{"ok": false, "status": "banned", "reason": client.BanReason}
	}
	if s.clientIsDraining(client.TokenID, client.ClientID) && strings.HasSuffix(r.URL.Path, "/bootstrap") {
		return nil, nil, nil, map[string]any{"ok": false, "status": "node_fault", "reason": "节点异常：请关闭全部穿透端口后重新登录"}
	}
	s.rememberClient(accessToken, client, strings.HasSuffix(r.URL.Path, "/resource-policy"))
	return token, user, client, nil
}

func protocolAllowed(protocol string, allowedProtocols []string) bool {
	for _, allowed := range allowedProtocols {
		if allowed == protocol {
			return true
		}
	}
	return false
}

func matchesAnyGrant(proxy db.ProxyAllocationInput, grants []db.PortGrant) bool {
	for _, grant := range grants {
		if !grant.Enabled || grant.Protocol != proxy.ProxyType {
			continue
		}
		switch proxy.ProxyType {
		case "tcp", "udp":
			if proxy.RemotePort >= grant.RemotePortStart && proxy.RemotePort <= grant.RemotePortEnd {
				return true
			}
		case "http", "https", "tcpmux":
			domainOK := grant.Domain == "" || grant.Domain == proxy.Domain
			subdomainOK := grant.Subdomain == "" || grant.Subdomain == proxy.Subdomain
			if domainOK && subdomainOK {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func (s *Server) renderFrpcConfig(user *db.User, leaseID, runtimeToken string, proxies []db.ProxyAllocationInput) string {
	cfg := s.getConfig()
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", cfg.ClientConfigComment)
	fmt.Fprintf(&b, "serverAddr = %q\n", cfg.FRPServerAddr)
	fmt.Fprintf(&b, "serverPort = %d\n", cfg.FRPServerPort)
	b.WriteString("loginFailExit = false\nlog.disablePrintColor = true\n")
	fmt.Fprintf(&b, "user = %q\n", fmt.Sprintf("u%d", user.ID))
	fmt.Fprintf(&b, "transport.tls.enable = %t\n", cfg.FRPTransportTLS)
	fmt.Fprintf(&b, "transport.tcpMux = %t\n", !cfg.ConnectionTuning.DisableTCPMux)
	if cfg.ConnectionTuning.TCPMuxKeepaliveSeconds > 0 {
		fmt.Fprintf(&b, "transport.tcpMuxKeepaliveInterval = %d\n", cfg.ConnectionTuning.TCPMuxKeepaliveSeconds)
	}
	fmt.Fprintf(&b, "metadatas.token = %q\n", runtimeToken)
	fmt.Fprintf(&b, "metadatas.lease_id = %q\n\n", leaseID)

	for _, proxy := range proxies {
		fmt.Fprintf(&b, "[[proxies]]\n")
		fmt.Fprintf(&b, "name = %q\n", leaseID+"."+proxy.ProxyName)
		fmt.Fprintf(&b, "type = %q\n", proxy.ProxyType)
		fmt.Fprintf(&b, "localIP = %q\n", proxy.LocalIP)
		fmt.Fprintf(&b, "localPort = %d\n", proxy.LocalPort)
		switch proxy.ProxyType {
		case "tcp", "udp":
			fmt.Fprintf(&b, "remotePort = %d\n", proxy.RemotePort)
		case "http", "https":
			if proxy.Domain != "" {
				fmt.Fprintf(&b, "customDomains = [%q]\n", proxy.Domain)
			}
			if proxy.Subdomain != "" {
				fmt.Fprintf(&b, "subdomain = %q\n", proxy.Subdomain)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
