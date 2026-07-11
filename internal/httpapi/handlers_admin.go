package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"frp-control-server/internal/db"
	"frp-control-server/internal/security"
)

type createUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": users})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if req.Role == "" {
		req.Role = "user"
	}
	if req.Role != "user" && req.Role != "admin" {
		writeError(w, http.StatusBadRequest, "unsupported role")
		return
	}
	if req.Role == "admin" && len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "admin password must be at least 8 characters")
		return
	}
	password := req.Password
	if req.Role == "user" {
		password = security.DisabledPasswordValue
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	admin := currentUser(r)
	if req.Role == "admin" {
		user, err := s.store.CreateUser(
			r.Context(),
			strings.TrimSpace(req.Username),
			strings.TrimSpace(req.DisplayName),
			hash,
			req.Role,
		)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := s.ensureAdminFixedToken(r, user.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.store.Audit(r.Context(), "admin", admin.ID, "create_user", "user", strconv.FormatInt(user.ID, 10), "admin account")
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "user": user})
		return
	}
	plain, tokenHash, err := security.NewOpaqueToken("ak_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	user, token, err := s.store.CreateUserWithAccessToken(
		r.Context(),
		strings.TrimSpace(req.Username),
		strings.TrimSpace(req.DisplayName),
		hash,
		req.Role,
		"HTTPS API Token",
		plain,
		tokenHash,
		security.TokenPrefix(plain),
		1,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.store.Audit(r.Context(), "admin", admin.ID, "create_user", "user", strconv.FormatInt(user.ID, 10), "")
	s.store.Audit(r.Context(), "admin", admin.ID, "create_token", "token", strconv.FormatInt(token.ID, 10), "default user API token")
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "user": user, "token": token, "plain_token": plain})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	admin := currentUser(r)
	if admin != nil && admin.ID == id {
		writeError(w, http.StatusBadRequest, "cannot delete the currently logged-in admin")
		return
	}
	terminated := 0
	if s.core != nil {
		terminated = s.core.TerminateConnectionsForUser(id)
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, db.ErrNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		case errors.Is(err, db.ErrLastAdmin):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.store.Audit(r.Context(), "admin", admin.ID, "delete_user", "user", strconv.FormatInt(id, 10), "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "terminated_connections": terminated})
}

type banRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) banUser(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	var req banRequest
	_ = readJSON(r, &req)
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "banned by administrator"
	}
	if err := s.store.SetUserStatus(r.Context(), id, "banned", req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	terminated := 0
	if s.core != nil {
		terminated = s.core.TerminateConnectionsForUser(id)
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "ban_user", "user", strconv.FormatInt(id, 10), req.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "terminated_connections": terminated})
}

func (s *Server) unbanUser(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if err := s.store.SetUserStatus(r.Context(), id, "active", ""); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "unban_user", "user", strconv.FormatInt(id, 10), "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) listUserPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListUserResourcePolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policies": policies})
}

func (s *Server) getUserPolicy(w http.ResponseWriter, r *http.Request) {
	userID, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	policy, err := s.store.GetUserResourcePolicy(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "policy not configured")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": policy})
}

type updateUserPolicyRequest struct {
	PortStart        int      `json:"port_start"`
	PortEnd          int      `json:"port_end"`
	MaxPorts         int      `json:"max_ports"`
	AllowedProtocols []string `json:"allowed_protocols"`
	Enabled          bool     `json:"enabled"`
}

func (s *Server) updateUserPolicy(w http.ResponseWriter, r *http.Request) {
	userID, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	var req updateUserPolicyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.PortStart <= 0 || req.PortEnd <= 0 || req.PortStart > req.PortEnd {
		writeError(w, http.StatusBadRequest, "invalid port range")
		return
	}
	if req.MaxPorts <= 0 {
		writeError(w, http.StatusBadRequest, "max_ports must be greater than zero")
		return
	}
	allowedProtocols := db.SplitProtocols(strings.Join(req.AllowedProtocols, ","))
	policy, err := s.store.UpsertUserResourcePolicy(r.Context(), db.UserResourcePolicy{
		UserID:           userID,
		PortStart:        req.PortStart,
		PortEnd:          req.PortEnd,
		MaxPorts:         req.MaxPorts,
		AllowedProtocols: allowedProtocols,
		Enabled:          req.Enabled,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "update_user_policy", "user", strconv.FormatInt(userID, 10), "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": policy})
}

type createTokenRequest struct {
	UserID        int64  `json:"user_id"`
	Name          string `json:"name"`
	MaxProxyCount int    `json:"max_proxy_count"`
	ExpiresAt     string `json:"expires_at"`
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.store.ListAccessTokens(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tokens": tokens})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.UserID <= 0 || strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "user_id and name are required")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "user not found")
		return
	}
	if user.Role != "user" {
		writeError(w, http.StatusBadRequest, "frp access tokens can only be assigned to user accounts")
		return
	}
	if req.MaxProxyCount <= 0 {
		req.MaxProxyCount = 1
	}
	var expires *time.Time
	if req.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		expires = &parsed
	}
	plain, hash, err := security.NewOpaqueToken("ak_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, err := s.store.CreateAccessToken(r.Context(), req.UserID, strings.TrimSpace(req.Name), plain, hash, security.TokenPrefix(plain), req.MaxProxyCount, expires)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "create_token", "token", strconv.FormatInt(token.ID, 10), "")
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "token": token, "plain_token": plain})
}

func (s *Server) banToken(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	var req banRequest
	_ = readJSON(r, &req)
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "banned by administrator"
	}
	if err := s.store.SetAccessTokenStatus(r.Context(), id, "banned", req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	terminated := 0
	if s.core != nil {
		terminated = s.core.TerminateConnectionsForToken(id)
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "ban_token", "token", strconv.FormatInt(id, 10), req.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "terminated_connections": terminated})
}

func (s *Server) rotateToken(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	plain, hash, err := security.NewOpaqueToken("ak_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, err := s.store.RotateAccessToken(r.Context(), id, plain, hash, security.TokenPrefix(plain))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "rotate_token", "token", strconv.FormatInt(id, 10), "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": token, "plain_token": plain})
}

func (s *Server) unbanToken(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	if err := s.store.SetAccessTokenStatus(r.Context(), id, "active", ""); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "unban_token", "token", strconv.FormatInt(id, 10), "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	tokenID, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	grants, err := s.store.ListPortGrants(r.Context(), tokenID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "grants": grants})
}

type createGrantRequest struct {
	Protocol        string `json:"protocol"`
	RemotePortStart int    `json:"remote_port_start"`
	RemotePortEnd   int    `json:"remote_port_end"`
	MaxCount        int    `json:"max_count"`
	Domain          string `json:"domain"`
	Subdomain       string `json:"subdomain"`
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	tokenID, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	var req createGrantRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	protocol := normalizeProtocol(req.Protocol)
	if protocol == "" {
		writeError(w, http.StatusBadRequest, "unsupported protocol")
		return
	}
	if req.RemotePortEnd == 0 {
		req.RemotePortEnd = req.RemotePortStart
	}
	if req.MaxCount <= 0 {
		req.MaxCount = 1
	}
	grant, err := s.store.CreatePortGrant(r.Context(), db.PortGrant{
		TokenID:         tokenID,
		Protocol:        protocol,
		RemotePortStart: req.RemotePortStart,
		RemotePortEnd:   req.RemotePortEnd,
		MaxCount:        req.MaxCount,
		Domain:          strings.TrimSpace(req.Domain),
		Subdomain:       strings.TrimSpace(req.Subdomain),
		Enabled:         true,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "create_grant", "token", strconv.FormatInt(tokenID, 10), "")
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "grant": grant})
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "clients": clients})
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid client id")
		return
	}
	client, err := s.store.GetClientByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "client not found")
		return
	}
	terminated := s.terminateClientRuntime(r.Context(), *client, "client deleted by administrator")
	deleted, err := s.store.DeleteClient(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "delete_client", "client", strconv.FormatInt(id, 10), deleted.ClientID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "client": deleted, "terminated_connections": terminated})
}

func (s *Server) banClient(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid client id")
		return
	}
	var req banRequest
	_ = readJSON(r, &req)
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "banned by administrator"
	}
	client, _ := s.store.GetClientByID(r.Context(), id)
	if err := s.store.SetClientStatus(r.Context(), id, "banned", req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	terminated := 0
	if s.core != nil && client != nil {
		terminated = s.core.TerminateConnectionsForClient(client.TokenID, client.ClientID)
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "ban_client", "client", strconv.FormatInt(id, 10), req.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "terminated_connections": terminated})
}

func (s *Server) unbanClient(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid client id")
		return
	}
	if err := s.store.SetClientStatus(r.Context(), id, "active", ""); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "unban_client", "client", strconv.FormatInt(id, 10), "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
