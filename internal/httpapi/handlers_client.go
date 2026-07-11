package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

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
			"reason": "resource policy is not configured",
		})
		return
	}
	if err := store.TouchClientHeartbeat(r.Context(), client.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg := s.getConfig()
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

	allocations, err := s.validateBootstrapProxies(r.Context(), user, token, req.Proxies)
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
	expiresAt := time.Now().Add(s.cfg.RuntimeTokenTTL)
	if err := store.CreateRuntimeLease(r.Context(), leaseID, user.ID, token.ID, req.ClientID, runtimeHash, security.TokenPrefix(runtimeToken), expiresAt, allocations); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	config := s.renderFrpcConfig(user, leaseID, runtimeToken, allocations)
	store.Audit(r.Context(), "client", client.ID, "bootstrap", "lease", leaseID, fmt.Sprintf("allocated %d proxies", len(allocations)))

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"lease_id":     leaseID,
		"expires_at":   expiresAt,
		"expires_in":   int(s.cfg.RuntimeTokenTTL.Seconds()),
		"frpc_config":  config,
		"allocations":  allocations,
		"frp_server":   s.cfg.FRPServerAddr,
		"frp_port":     s.cfg.FRPServerPort,
		"token_prefix": security.TokenPrefix(runtimeToken),
	})
}

func (s *Server) validateBootstrapProxies(ctx context.Context, user *db.User, token *db.AccessToken, proxies []db.ProxyAllocationInput) ([]db.ProxyAllocationInput, error) {
	if len(proxies) == 0 {
		return nil, fmt.Errorf("at least one proxy is required")
	}
	policy, err := s.store.GetUserResourcePolicy(ctx, user.ID)
	if err != nil || !policy.Enabled {
		return nil, fmt.Errorf("resource policy is not configured")
	}
	if policy.MaxPorts > 0 && len(proxies) > policy.MaxPorts {
		return nil, fmt.Errorf("proxy count %d exceeds user limit %d", len(proxies), policy.MaxPorts)
	}
	if token.MaxProxyCount > 0 && len(proxies) > token.MaxProxyCount {
		return nil, fmt.Errorf("proxy count %d exceeds token limit %d", len(proxies), token.MaxProxyCount)
	}
	grants, _ := s.store.ListPortGrants(ctx, token.ID)
	var normalized []db.ProxyAllocationInput
	for _, proxy := range proxies {
		proxy.ProxyName = strings.TrimSpace(proxy.ProxyName)
		proxy.ProxyType = normalizeProtocol(proxy.ProxyType)
		proxy.LocalIP = strings.TrimSpace(proxy.LocalIP)
		proxy.Domain = strings.TrimSpace(proxy.Domain)
		proxy.Subdomain = strings.TrimSpace(proxy.Subdomain)
		if proxy.ProxyName == "" || proxy.ProxyType == "" || proxy.LocalPort <= 0 {
			return nil, fmt.Errorf("proxy name, supported type and local_port are required")
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
		return nil, nil, nil, map[string]any{"ok": false, "status": "unauthorized", "reason": "invalid access token"}
	}
	user, err := store.GetUserByID(r.Context(), token.UserID)
	if err != nil {
		return nil, nil, nil, map[string]any{"ok": false, "status": "unauthorized", "reason": "invalid token owner"}
	}
	if user.Role != "user" {
		return nil, nil, nil, map[string]any{"ok": false, "status": "unauthorized", "reason": "admin accounts cannot use frp access"}
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
			return nil, nil, nil, map[string]any{"ok": false, "status": "error", "reason": err.Error()}
		}
	} else {
		client, err = store.GetClient(r.Context(), token.ID, clientID)
		if err != nil {
			return nil, nil, nil, map[string]any{"ok": false, "status": "heartbeat_required", "reason": "client heartbeat is required before bootstrap"}
		}
	}
	if client.Status == "banned" {
		return nil, nil, nil, map[string]any{"ok": false, "status": "banned", "reason": client.BanReason}
	}
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
	fmt.Fprintf(&b, "user = %q\n", fmt.Sprintf("u%d", user.ID))
	if cfg.FRPTransportTLS {
		b.WriteString("transport.tls.enable = true\n")
	}
	fmt.Fprintf(&b, "metadatas.token = %q\n", runtimeToken)
	fmt.Fprintf(&b, "metadatas.lease_id = %q\n\n", leaseID)

	for _, proxy := range proxies {
		fmt.Fprintf(&b, "[[proxies]]\n")
		fmt.Fprintf(&b, "name = %q\n", proxy.ProxyName)
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
