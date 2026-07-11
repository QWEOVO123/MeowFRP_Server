package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"frp-control-server/internal/db"
	"frp-control-server/internal/frpcore"
	"frp-control-server/internal/policy"
	"frp-control-server/internal/security"
)

type frpPluginRequest struct {
	Version string          `json:"version"`
	Op      string          `json:"op"`
	Content json.RawMessage `json:"content"`
}

type frpPluginResponse struct {
	Reject       bool   `json:"reject"`
	RejectReason string `json:"reject_reason,omitempty"`
	Unchange     bool   `json:"unchange,omitempty"`
}

type frpUserInfo struct {
	User  string            `json:"user"`
	Metas map[string]string `json:"metas"`
	RunID string            `json:"run_id"`
}

type frpLoginContent struct {
	User          string            `json:"user"`
	RunID         string            `json:"run_id"`
	Metas         map[string]string `json:"metas"`
	ClientAddress string            `json:"client_address"`
}

type frpNewProxyContent struct {
	User          frpUserInfo       `json:"user"`
	ProxyName     string            `json:"proxy_name"`
	ProxyType     string            `json:"proxy_type"`
	RemotePort    int               `json:"remote_port"`
	CustomDomains []string          `json:"custom_domains"`
	Subdomain     string            `json:"subdomain"`
	Metas         map[string]string `json:"metas"`
}

type frpCloseProxyContent struct {
	User      frpUserInfo `json:"user"`
	ProxyName string      `json:"proxy_name"`
}

type frpPingContent struct {
	User frpUserInfo `json:"user"`
}

type frpNewWorkConnContent struct {
	User  frpUserInfo `json:"user"`
	RunID string      `json:"run_id"`
}

type frpNewUserConnContent struct {
	User       frpUserInfo `json:"user"`
	ProxyName  string      `json:"proxy_name"`
	ProxyType  string      `json:"proxy_type"`
	RemoteAddr string      `json:"remote_addr"`
}

func (s *Server) frpPlugin(w http.ResponseWriter, r *http.Request) {
	if s.getStore() == nil {
		writeJSON(w, http.StatusOK, frpReject("system setup required"))
		return
	}
	var req frpPluginRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusOK, frpReject("bad plugin request: "+err.Error()))
		return
	}
	switch req.Op {
	case "Login":
		s.handleFrpLogin(w, r, req.Content)
	case "NewProxy":
		s.handleFrpNewProxy(w, r, req.Content)
	case "CloseProxy":
		s.handleFrpCloseProxy(w, r, req.Content)
	case "Ping", "NewWorkConn", "NewUserConn":
		s.handleFrpRuntimeKeepalive(w, r, req.Op, req.Content)
	default:
		writeJSON(w, http.StatusOK, frpAllow())
	}
}

func (s *Server) handleFrpLogin(w http.ResponseWriter, r *http.Request, raw json.RawMessage) {
	var content frpLoginContent
	if err := json.Unmarshal(raw, &content); err != nil {
		writeJSON(w, http.StatusOK, frpReject("bad Login content"))
		return
	}
	lease, reject := s.validateRuntime(r, content.Metas)
	if reject != "" {
		writeJSON(w, http.StatusOK, frpReject(reject))
		return
	}
	if decision := s.policy.BeforeFrpLogin(r.Context(), policy.FrpLoginInput{
		UserID: lease.UserID, TokenID: lease.TokenID, ClientID: lease.ClientID, LeaseID: lease.LeaseID, RunID: content.RunID,
	}); decision.Action != policy.ActionAllow {
		writeJSON(w, http.StatusOK, frpReject(decision.Reason))
		return
	}
	clientAddress := clientAddressHost(content.ClientAddress)
	if s.core != nil {
		s.core.SetLeaseClientAddress(lease.LeaseID, clientAddress)
	}
	if clientAddress != "" {
		_ = s.store.UpdateClientFRPCAddress(r.Context(), lease.TokenID, lease.ClientID, clientAddress)
	}
	writeJSON(w, http.StatusOK, frpAllow())
}

func clientAddressHost(addr string) string {
	addr = strings.TrimSpace(addr)
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return addr
}

func (s *Server) handleFrpNewProxy(w http.ResponseWriter, r *http.Request, raw json.RawMessage) {
	var content frpNewProxyContent
	if err := json.Unmarshal(raw, &content); err != nil {
		writeJSON(w, http.StatusOK, frpReject("bad NewProxy content"))
		return
	}
	lease, reject := s.validateRuntime(r, content.User.Metas)
	if reject != "" {
		writeJSON(w, http.StatusOK, frpReject(reject))
		return
	}
	proxyType := normalizeProtocol(content.ProxyType)
	if proxyType == "" {
		writeJSON(w, http.StatusOK, frpReject("unsupported proxy type"))
		return
	}
	domain := first(content.CustomDomains)
	subdomain := strings.TrimSpace(content.Subdomain)
	allocationName := stripFRPUserProxyPrefix(lease.UserID, content.ProxyName)
	if _, err := s.store.GetLeaseAllocation(r.Context(), lease.LeaseID, allocationName, proxyType, content.RemotePort, domain, subdomain); err != nil {
		writeJSON(w, http.StatusOK, frpReject("proxy is not allocated by current lease"))
		return
	}
	token, err := s.store.GetAccessTokenByID(r.Context(), lease.TokenID)
	if err != nil || token.Status != "active" {
		writeJSON(w, http.StatusOK, frpReject("token is not active"))
		return
	}
	activeCount, err := s.store.CountActiveProxySessions(r.Context(), lease.TokenID)
	if err != nil {
		writeJSON(w, http.StatusOK, frpReject("failed to count active proxies"))
		return
	}
	if token.MaxProxyCount > 0 && activeCount >= token.MaxProxyCount {
		writeJSON(w, http.StatusOK, frpReject(fmt.Sprintf("token max proxy count %d reached", token.MaxProxyCount)))
		return
	}
	if decision := s.policy.BeforeProxyCreate(r.Context(), policy.ProxyCreateInput{
		UserID: lease.UserID, TokenID: lease.TokenID, ClientID: lease.ClientID, LeaseID: lease.LeaseID,
		ProxyName: content.ProxyName, ProxyType: proxyType, RemotePort: content.RemotePort, Domain: domain, Subdomain: subdomain,
	}); decision.Action != policy.ActionAllow {
		writeJSON(w, http.StatusOK, frpReject(decision.Reason))
		return
	}
	if err := s.store.StartProxySession(r.Context(), *lease, content.ProxyName, proxyType, content.RemotePort, domain, subdomain, content.User.RunID); err != nil {
		writeJSON(w, http.StatusOK, frpReject("failed to record proxy session"))
		return
	}
	if s.core != nil {
		s.core.BindProxy(frpcore.ProxyBinding{
			UserID:     lease.UserID,
			TokenID:    lease.TokenID,
			ClientID:   lease.ClientID,
			ClientAddr: s.coreClientAddress(lease.LeaseID),
			LeaseID:    lease.LeaseID,
			ProxyName:  content.ProxyName,
			ProxyType:  proxyType,
			RemotePort: content.RemotePort,
		})
	}
	s.policy.OnProxyStarted(r.Context(), policy.ProxyEvent{LeaseID: lease.LeaseID, ProxyName: content.ProxyName, ProxyType: proxyType, RemotePort: content.RemotePort})
	writeJSON(w, http.StatusOK, frpAllow())
}

func (s *Server) coreClientAddress(leaseID string) string {
	if s.core == nil {
		return ""
	}
	for _, conn := range s.core.ListConnections(10 * time.Second) {
		if conn.LeaseID == leaseID && conn.ClientAddr != "" {
			return conn.ClientAddr
		}
	}
	return ""
}

func (s *Server) handleFrpCloseProxy(w http.ResponseWriter, r *http.Request, raw json.RawMessage) {
	var content frpCloseProxyContent
	if err := json.Unmarshal(raw, &content); err != nil {
		writeJSON(w, http.StatusOK, frpAllow())
		return
	}
	leaseID := content.User.Metas["lease_id"]
	if leaseID != "" && content.ProxyName != "" {
		_ = s.store.CloseProxySession(r.Context(), leaseID, content.ProxyName, "frp close proxy")
		if s.core != nil {
			s.core.UnbindProxy(leaseID, content.ProxyName)
		}
		s.policy.OnProxyClosed(r.Context(), policy.ProxyEvent{LeaseID: leaseID, ProxyName: content.ProxyName, Reason: "frp close proxy"})
	}
	writeJSON(w, http.StatusOK, frpAllow())
}

func (s *Server) handleFrpRuntimeKeepalive(w http.ResponseWriter, r *http.Request, op string, raw json.RawMessage) {
	metas := map[string]string{}
	switch op {
	case "Ping":
		var content frpPingContent
		_ = json.Unmarshal(raw, &content)
		metas = content.User.Metas
	case "NewWorkConn":
		var content frpNewWorkConnContent
		_ = json.Unmarshal(raw, &content)
		metas = content.User.Metas
	case "NewUserConn":
		var content frpNewUserConnContent
		_ = json.Unmarshal(raw, &content)
		metas = content.User.Metas
	}
	if _, reject := s.validateRuntime(r, metas); reject != "" {
		writeJSON(w, http.StatusOK, frpReject(reject))
		return
	}
	writeJSON(w, http.StatusOK, frpAllow())
}

func (s *Server) validateRuntime(r *http.Request, metas map[string]string) (*db.RuntimeLease, string) {
	runtimeToken := metas["token"]
	leaseID := metas["lease_id"]
	if runtimeToken == "" || leaseID == "" {
		return nil, "missing runtime token or lease_id"
	}
	lease, err := s.store.GetRuntimeLeaseByTokenHash(r.Context(), security.TokenHash(runtimeToken))
	if errors.Is(err, db.ErrNotFound) {
		return nil, "invalid runtime token"
	}
	if err != nil {
		return nil, "runtime token lookup failed"
	}
	if lease.LeaseID != leaseID {
		return nil, "runtime token and lease_id mismatch"
	}
	if lease.Status != "active" || time.Now().After(lease.ExpiresAt) {
		return nil, "runtime lease expired or inactive"
	}
	user, err := s.store.GetUserByID(r.Context(), lease.UserID)
	if err != nil || user.Status != "active" {
		if user != nil && user.Status == "banned" && user.BanReason != "" {
			return nil, user.BanReason
		}
		return nil, "user is not active"
	}
	token, err := s.store.GetAccessTokenByID(r.Context(), lease.TokenID)
	if err != nil || token.Status != "active" {
		if token != nil && token.Status == "banned" && token.BanReason != "" {
			return nil, token.BanReason
		}
		return nil, "token is not active"
	}
	client, err := s.store.GetClient(r.Context(), lease.TokenID, lease.ClientID)
	if err != nil || client.Status != "active" {
		if client != nil && client.Status == "banned" && client.BanReason != "" {
			return nil, client.BanReason
		}
		return nil, "client is not active"
	}
	fresh, err := s.store.IsClientHeartbeatFresh(r.Context(), client.ID, int(clientHeartbeatTimeout.Seconds()))
	if err != nil || !fresh {
		s.terminateClientRuntime(r.Context(), *client, "client heartbeat timeout")
		return nil, "client heartbeat timeout"
	}
	return lease, ""
}

func frpAllow() frpPluginResponse {
	return frpPluginResponse{Reject: false, Unchange: true}
}

func frpReject(reason string) frpPluginResponse {
	if strings.TrimSpace(reason) == "" {
		reason = "rejected by policy"
	}
	return frpPluginResponse{Reject: true, RejectReason: reason}
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func stripFRPUserProxyPrefix(userID int64, proxyName string) string {
	prefix := fmt.Sprintf("u%d.", userID)
	if trimmed, ok := strings.CutPrefix(proxyName, prefix); ok {
		return trimmed
	}
	return proxyName
}
